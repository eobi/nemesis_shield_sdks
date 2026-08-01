<?php
/**
 * Nemesis Shield: brute-force login protection.
 *
 * A complement to the behavioral shield. Brute force can't be caught by request-shape modeling (a
 * malicious login looks identical to a real one), so this module counts failed logins per IP and
 * time-boxes a lockout once a threshold is crossed. Covers wp-login, XML-RPC and application-password
 * auth (all flow through the `authenticate` filter). Lockouts auto-expire and can be cleared by an
 * admin, and the whole module can be bypassed with a constant, so it can never permanently lock you out.
 *
 * @package Nemesis_Shield
 */

if (!defined('ABSPATH')) {
    exit;
}

class Nemesis_Shield_Login_Guard
{
    const OPT = 'nemesis_shield_options';
    const LOCKS = 'nemesis_shield_lockouts'; // option: hash => array(ip, until, user)

    public static function init()
    {
        if (!self::enabled()) {
            return;
        }
        // Block first (priority 30, after WordPress's own auth at 20), so a locked IP is refused before
        // any credential check. Count failures, and clear the counter on a real login.
        add_filter('authenticate', array(__CLASS__, 'check_lock'), 30, 3);
        add_action('wp_login_failed', array(__CLASS__, 'on_failed'), 10, 1);
        add_action('wp_login', array(__CLASS__, 'on_success'), 10, 2);
    }

    private static function enabled()
    {
        if (defined('NEMESIS_SHIELD_DISABLE_LOGIN_GUARD') && NEMESIS_SHIELD_DISABLE_LOGIN_GUARD) {
            return false;
        }
        return self::opt('login_guard', '1') === '1';
    }

    // ---- settings ----
    private static function opt($k, $default = '')
    {
        $o = get_option(self::OPT, array());
        return (is_array($o) && isset($o[$k])) ? $o[$k] : $default;
    }
    private static function max_attempts()
    {
        return max(1, (int) self::opt('lg_max', 5));
    }
    private static function window()
    {
        return max(60, (int) self::opt('lg_window', 900)); // seconds the failure counter accumulates over
    }
    private static function lockout()
    {
        return max(60, (int) self::opt('lg_lockout', 1800)); // seconds a lockout lasts
    }

    // ---- ip + keys ----
    public static function client_ip()
    {
        $ip = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '';
        // Sites behind a trusted proxy/CDN can supply the real client IP via this filter.
        $ip = apply_filters('nemesis_shield_client_ip', $ip);
        return is_string($ip) ? $ip : '';
    }
    private static function hash($ip)
    {
        return substr(hash('sha256', 'ns_lg|' . $ip), 0, 32);
    }
    private static function counter_key($ip)
    {
        return 'nemesis_shield_fails_' . self::hash($ip);
    }

    // ---- lockouts (option-backed so admins can see + clear them) ----
    private static function lockouts()
    {
        $l = get_option(self::LOCKS, array());
        return is_array($l) ? $l : array();
    }
    private static function prune(array $l)
    {
        $now = time();
        foreach ($l as $h => $rec) {
            if (!is_array($rec) || (int) ($rec['until'] ?? 0) <= $now) {
                unset($l[$h]);
            }
        }
        return $l;
    }

    public static function is_locked($ip)
    {
        if ($ip === '') {
            return false;
        }
        $l = self::prune(self::lockouts());
        $h = self::hash($ip);
        return isset($l[$h]);
    }

    private static function lock($ip, $user)
    {
        $l = self::prune(self::lockouts());
        $l[self::hash($ip)] = array(
            'ip'    => $ip,
            'user'  => (string) $user,
            'until' => time() + self::lockout(),
            'at'    => time(),
        );
        update_option(self::LOCKS, $l, false);
    }

    private static function unlock_ip($ip)
    {
        $l = self::prune(self::lockouts());
        unset($l[self::hash($ip)]);
        update_option(self::LOCKS, $l, false);
        delete_transient(self::counter_key($ip));
    }

    /** Active (non-expired) lockouts for the admin screen: array of array(ip, user, until, at). */
    public static function active_lockouts()
    {
        $l = self::prune(self::lockouts());
        // Persist the pruned set so expired rows don't linger.
        update_option(self::LOCKS, $l, false);
        return array_values($l);
    }

    /** Admin action: clear one lockout (nonce + capability checked by the caller). */
    public static function admin_unlock($ip)
    {
        self::unlock_ip($ip);
    }

    // ---- hooks ----

    /** Refuse authentication from a locked-out IP before any credential is checked. */
    public static function check_lock($user, $username, $password)
    {
        // Don't interfere with an empty submit (WordPress shows its own "empty username" notice).
        if ($username === '' && $password === '') {
            return $user;
        }
        $ip = self::client_ip();
        if (self::is_locked($ip)) {
            return new WP_Error(
                'nemesis_shield_locked',
                esc_html__('Too many failed login attempts. Please try again later.', 'nemesis-shield')
            );
        }
        return $user;
    }

    /** Count a failed login; lock the IP once the threshold is crossed within the window. */
    public static function on_failed($username)
    {
        $ip = self::client_ip();
        if ($ip === '') {
            return;
        }
        $key = self::counter_key($ip);
        $n = (int) get_transient($key);
        $n++;
        set_transient($key, $n, self::window());
        if ($n >= self::max_attempts()) {
            self::lock($ip, $username);
            delete_transient($key);
            self::report($ip, (string) $username, $n);
        }
    }

    /** A real login clears the failure counter and any lockout for that IP. */
    public static function on_success($user_login, $user)
    {
        self::unlock_ip(self::client_ip());
    }

    /**
     * Best-effort telemetry to the Nemesis service (so the console shows brute-force activity alongside
     * behavioral events). Never blocks and never surfaces errors; skipped when no token is configured.
     */
    private static function report($ip, $username, $attempts)
    {
        $token = self::token();
        if ($token === '' || !function_exists('wp_remote_post')) {
            return;
        }
        $endpoint = defined('NEMESIS_SHIELD_ENDPOINT') && NEMESIS_SHIELD_ENDPOINT
            ? NEMESIS_SHIELD_ENDPOINT
            : 'https://shield.nemesislabs.xyz/api/v1/sketches';
        // Reuse the sketches channel with a login-lockout signal. Values are minimal; no password ever.
        wp_remote_post($endpoint, array(
            'headers'  => array('Authorization' => 'Bearer ' . $token, 'Content-Type' => 'application/json'),
            'body'     => wp_json_encode(array('events' => array(array(
                'kind'     => 'login_lockout',
                'ip'       => $ip,
                'attempts' => (int) $attempts,
            )))),
            'timeout'  => 2,
            'blocking' => false, // fire-and-forget; never slow down the login response
        ));
    }

    private static function token()
    {
        if (defined('NEMESIS_SHIELD_TOKEN') && NEMESIS_SHIELD_TOKEN) {
            return (string) NEMESIS_SHIELD_TOKEN;
        }
        if (($env = getenv('NEMESIS_TOKEN')) !== false && $env !== '') {
            return (string) $env;
        }
        return (string) self::opt('token', '');
    }
}
