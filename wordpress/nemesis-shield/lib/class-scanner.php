<?php
/**
 * Nemesis Shield: file-integrity and malware scanner.
 *
 * A complement to the behavioral shield. Behavioral protection is a request-time shield; it blocks a
 * backdoor's *use* but cannot see a malicious file sitting on disk (a site that was already compromised,
 * or a backdoor triggered out-of-band). This module scans the filesystem:
 *
 *   1. Core integrity: verify WordPress core files against the official WordPress.org checksums.
 *   2. Malware heuristics: scan wp-content PHP for high-signal backdoor/obfuscation patterns.
 *   3. PHP in uploads: any executable PHP under the uploads directory is flagged (a classic sign).
 *
 * Runs on a daily cron and on demand. Reads go through WP_Filesystem. Bounded by file-size, file-count
 * and time budgets so it can never hang a request. Results are stored locally and can be surfaced to
 * the Nemesis console.
 *
 * @package Nemesis_Shield
 */

if (!defined('ABSPATH')) {
    exit;
}

class Nemesis_Shield_Scanner
{
    const RESULT = 'nemesis_shield_scan';
    const CRON = 'nemesis_shield_daily_scan';
    const MAX_FILE = 2097152;   // 2 MB: skip larger files
    const MAX_FILES = 30000;    // hard cap on files inspected
    const TIME_BUDGET = 25;     // seconds

    // High-signal malware / obfuscation patterns (data, never executed). Tuned for low false positives.
    private static function patterns()
    {
        return array(
            'eval-decoded'      => '/\beval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|rawurldecode|hex2bin)\s*\(/i',
            'eval-superglobal'  => '/\beval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)\b/i',
            'assert-superglobal' => '/\bassert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\b/i',
            'preg-replace-e'    => '/\bpreg_replace\s*\(\s*[\'"][^\'"]*\/[a-zA-Z]*e[a-zA-Z]*[\'"]/i',
            'create-function'   => '/\bcreate_function\s*\(/i',
            'exec-superglobal'  => '/\b(system|shell_exec|passthru|proc_open|popen|exec)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\b/i',
            'gzinflate-base64'  => '/\bgzinflate\s*\(\s*base64_decode\s*\(/i',
            'long-base64-eval'  => '/(eval|assert)\s*\(.{0,40}base64_decode\s*\(\s*[\'"][A-Za-z0-9+\/=]{150,}/i',
            'known-shell'       => '/\b(c99shell|r57shell|b374k|WSO\s*[0-9.]|FilesMan|weevely|phpspy)\b/i',
            'callback-super'    => '/\b(call_user_func|call_user_func_array)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\b/i',
            'variable-function-super' => '/\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\]\s*\(/',
        );
    }

    public static function schedule()
    {
        if (!wp_next_scheduled(self::CRON)) {
            wp_schedule_event(time() + 300, 'daily', self::CRON);
        }
    }
    public static function unschedule()
    {
        $ts = wp_next_scheduled(self::CRON);
        if ($ts) {
            wp_unschedule_event($ts, self::CRON);
        }
    }
    public static function init()
    {
        add_action(self::CRON, array(__CLASS__, 'scan'));
    }

    /** Scan a single string of code for malware patterns. Returns array of matched pattern keys. */
    public static function scan_string($code)
    {
        $hits = array();
        foreach (self::patterns() as $key => $re) {
            if (preg_match($re, $code)) {
                $hits[] = $key;
            }
        }
        return $hits;
    }

    private static function fs()
    {
        global $wp_filesystem;
        if (!$wp_filesystem) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
            WP_Filesystem();
        }
        return $wp_filesystem;
    }

    /** Read a file (bounded) through WP_Filesystem; '' on failure. */
    private static function read($path)
    {
        $fs = self::fs();
        if (!$fs) {
            return '';
        }
        $c = $fs->get_contents($path);
        return is_string($c) ? $c : '';
    }

    /** The line number of the first pattern match, for the report. */
    private static function first_line($code)
    {
        foreach (self::patterns() as $re) {
            if (preg_match($re, $code, $m, PREG_OFFSET_CAPTURE)) {
                return substr_count(substr($code, 0, $m[0][1]), "\n") + 1;
            }
        }
        return 0;
    }

    /**
     * Run the full scan. Returns and stores a result array:
     *   ts, duration, scanned, core_modified[], suspicious[{file,patterns,line}], php_in_uploads[]
     */
    public static function scan()
    {
        $start = time();
        $result = array(
            'ts' => gmdate('Y-m-d H:i:s'),
            'duration' => 0,
            'scanned' => 0,
            'core_modified' => array(),
            'suspicious' => array(),
            'php_in_uploads' => array(),
            'incomplete' => false,
        );

        // 1. Core integrity via the official WordPress.org checksums.
        $result['core_modified'] = self::check_core();

        // 2 + 3. Malware heuristics over wp-content, and PHP under uploads.
        $roots = array(WP_CONTENT_DIR);
        $uploads = wp_upload_dir();
        $uploads_base = isset($uploads['basedir']) ? $uploads['basedir'] : '';
        $count = 0;
        foreach ($roots as $root) {
            if (!is_dir($root)) {
                continue;
            }
            try {
                $it = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
                    RecursiveIteratorIterator::LEAVES_ONLY
                );
            } catch (\Throwable $e) {
                unset($e);
                continue;
            }
            foreach ($it as $file) {
                if ($count >= self::MAX_FILES || (time() - $start) > self::TIME_BUDGET) {
                    $result['incomplete'] = true;
                    break;
                }
                $path = $file->getPathname();
                $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
                $is_php = in_array($ext, array('php', 'phtml', 'php5', 'php7', 'phar'), true);
                if (!$is_php) {
                    continue;
                }
                // Any executable PHP living under uploads is a strong red flag on its own.
                if ($uploads_base !== '' && strpos($path, $uploads_base) === 0) {
                    $result['php_in_uploads'][] = self::rel($path);
                }
                if ($file->getSize() > self::MAX_FILE) {
                    continue;
                }
                $count++;
                $code = self::read($path);
                if ($code === '') {
                    continue;
                }
                $hits = self::scan_string($code);
                if ($hits) {
                    $result['suspicious'][] = array(
                        'file' => self::rel($path),
                        'patterns' => $hits,
                        'line' => self::first_line($code),
                    );
                }
            }
        }
        $result['scanned'] = $count;
        $result['duration'] = time() - $start;
        update_option(self::RESULT, $result, false);
        self::report($result);
        return $result;
    }

    /** Compare core files to WordPress.org checksums; return relative paths that differ. */
    private static function check_core()
    {
        global $wp_version;
        require_once ABSPATH . 'wp-admin/includes/update.php';
        if (!function_exists('get_core_checksums')) {
            return array();
        }
        $locale = function_exists('get_locale') ? get_locale() : 'en_US';
        $sums = get_core_checksums($wp_version, $locale);
        if (empty($sums) || !is_array($sums)) {
            return array();
        }
        $modified = array();
        $start = time();
        foreach ($sums as $rel => $md5) {
            if ((time() - $start) > self::TIME_BUDGET) {
                break;
            }
            // wp-content is user territory and not covered by core checksums.
            if (strpos($rel, 'wp-content/') === 0) {
                continue;
            }
            $abs = ABSPATH . $rel;
            if (!file_exists($abs)) {
                continue; // absent optional files are not "modified"
            }
            $code = self::read($abs);
            if ($code === '' || md5($code) !== $md5) {
                $modified[] = $rel;
            }
        }
        return $modified;
    }

    private static function rel($path)
    {
        $base = defined('ABSPATH') ? ABSPATH : '';
        return $base && strpos($path, $base) === 0 ? substr($path, strlen($base)) : $path;
    }

    /** The stored result of the last scan, or null. */
    public static function last()
    {
        $r = get_option(self::RESULT, null);
        return is_array($r) ? $r : null;
    }

    /** Total number of issues in a result. */
    public static function issue_count($r)
    {
        if (!is_array($r)) {
            return 0;
        }
        return count($r['core_modified'] ?? array()) + count($r['suspicious'] ?? array()) + count($r['php_in_uploads'] ?? array());
    }

    /** Best-effort summary to the Nemesis service (fire-and-forget; skipped with no token). */
    private static function report($result)
    {
        $token = '';
        if (defined('NEMESIS_SHIELD_TOKEN') && NEMESIS_SHIELD_TOKEN) {
            $token = (string) NEMESIS_SHIELD_TOKEN;
        } elseif (($env = getenv('NEMESIS_TOKEN')) !== false && $env !== '') {
            $token = (string) $env;
        } else {
            $o = get_option('nemesis_shield_options', array());
            $token = is_array($o) ? (string) ($o['token'] ?? '') : '';
        }
        if ($token === '' || !function_exists('wp_remote_post')) {
            return;
        }
        $endpoint = defined('NEMESIS_SHIELD_ENDPOINT') && NEMESIS_SHIELD_ENDPOINT
            ? NEMESIS_SHIELD_ENDPOINT
            : 'https://shield.nemesislabs.xyz/api/v1/sketches';
        wp_remote_post($endpoint, array(
            'headers'  => array('Authorization' => 'Bearer ' . $token, 'Content-Type' => 'application/json'),
            'body'     => wp_json_encode(array('events' => array(array(
                'kind' => 'scan_summary',
                'issues' => self::issue_count($result),
                'core_modified' => count($result['core_modified'] ?? array()),
                'suspicious' => count($result['suspicious'] ?? array()),
                'php_in_uploads' => count($result['php_in_uploads'] ?? array()),
                'scanned' => (int) ($result['scanned'] ?? 0),
            )))),
            'timeout'  => 3,
            'blocking' => false,
        ));
    }
}
