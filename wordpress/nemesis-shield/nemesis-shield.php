<?php
/**
 * Plugin Name:       Nemesis Shield
 * Plugin URI:        https://shield.nemesislabs.xyz
 * Description:       Positive-security runtime protection for WordPress. Learns your site's normal behaviour and, in enforce mode, blocks off-baseline requests (auth bypass, path traversal, scanners, unusual methods) before WordPress runs. Privacy-preserving, fail-open.
 * Version:           1.0.0
 * Requires at least: 5.0
 * Requires PHP:      7.2
 * Author:            Nemesis Labs
 * Author URI:        https://nemesislabs.xyz
 * License:           MIT
 * Text Domain:       nemesis-shield
 *
 * How it works: the same native PHP SDK every Nemesis Shield integration uses. It
 * computes a privacy-preserving *shape* of each request locally (method + path
 * shape + param kinds + auth flag — never bodies, values, or secrets), caches the
 * compiled policy, and makes the block decision in-process. Observe → approve in
 * the console → enforce. Fail-open: if Shield is unreachable, the site is
 * unaffected. WordPress admin, login and cron are never blocked unless you opt in.
 */

if (!defined('ABSPATH')) {
    exit; // no direct access
}

require_once __DIR__ . '/lib/NemesisShield.php';
require_once __DIR__ . '/lib/NemesisShieldLLM.php';

final class Nemesis_Shield_Plugin
{
    const OPT = 'nemesis_shield_options';
    const VERSION = '1.0.0';

    /** Cache the resolved token so we don't recompute it on every hook. */
    private static $token = null;
    private static $blocked = false; // guard against double-blocking within one request

    public static function boot()
    {
        // Let a wp-config constant point the SDK at a self-hosted / on-prem Shield.
        $ep = self::opt('endpoint', '');
        if ($ep !== '' && !defined('NEMESIS_SHIELD_ENDPOINT')) {
            define('NEMESIS_SHIELD_ENDPOINT', $ep);
        }

        // Gate: run as early as auth state is reliable. On `init` is_user_logged_in()
        // works, and it fires for the front end, wp-admin, and admin-ajax alike —
        // before the main query / template does its work.
        add_action('init', array(__CLASS__, 'gate'), PHP_INT_MIN);

        // REST gets its own pre-dispatch gate so we can block with a proper JSON 403
        // before the route handler runs, with REST auth already resolved.
        add_filter('rest_pre_dispatch', array(__CLASS__, 'gate_rest'), PHP_INT_MIN, 3);

        // Observe every request at the very end, once the status code exists.
        add_action('shutdown', array(__CLASS__, 'observe'), PHP_INT_MAX);

        if (is_admin()) {
            add_action('admin_menu', array(__CLASS__, 'menu'));
            add_action('admin_init', array(__CLASS__, 'register_settings'));
        }
    }

    // ---- config ---------------------------------------------------------------

    private static function options()
    {
        $o = get_option(self::OPT, array());
        return is_array($o) ? $o : array();
    }

    private static function opt($k, $default = '')
    {
        $o = self::options();
        return isset($o[$k]) ? $o[$k] : $default;
    }

    /**
     * Token precedence: NEMESIS_SHIELD_TOKEN constant (wp-config) > NEMESIS_TOKEN
     * env > the value saved in Settings. Constants/env keep the secret out of the DB.
     */
    private static function token()
    {
        if (self::$token !== null) {
            return self::$token;
        }
        $t = '';
        if (defined('NEMESIS_SHIELD_TOKEN') && NEMESIS_SHIELD_TOKEN) {
            $t = (string) NEMESIS_SHIELD_TOKEN;
        } elseif (($env = getenv('NEMESIS_TOKEN')) !== false && $env !== '') {
            $t = (string) $env;
        } else {
            $t = (string) self::opt('token', '');
        }
        return self::$token = trim($t);
    }

    // ---- request extraction ---------------------------------------------------

    private static function method()
    {
        return isset($_SERVER['REQUEST_METHOD']) ? (string) $_SERVER['REQUEST_METHOD'] : 'GET';
    }

    private static function path()
    {
        $uri = isset($_SERVER['REQUEST_URI']) ? (string) $_SERVER['REQUEST_URI'] : '/';
        return '/' . ltrim(strtok($uri, '?'), '/');
    }

    private static function authed()
    {
        if (function_exists('is_user_logged_in') && is_user_logged_in()) {
            return true;
        }
        // API callers (application passwords, bearer/basic) show up as headers. Apache's
        // common "pass the Authorization header" rewrite sets these to an EMPTY string on
        // anonymous requests, so test for a non-empty value, not mere presence — otherwise
        // every visitor would be mislabelled authenticated and poison the baseline.
        $h = isset($_SERVER['HTTP_AUTHORIZATION']) ? $_SERVER['HTTP_AUTHORIZATION']
           : (isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION']) ? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] : '');
        return is_string($h) && $h !== '';
    }

    /**
     * Whether we should *enforce* (block) on this request. Observation always runs;
     * blocking is held back on the surfaces that could lock an operator out unless
     * they explicitly opt in. Login and cron are never blocked; WP-CLI is exempt.
     */
    private static function enforceable()
    {
        if (defined('WP_CLI') && WP_CLI) {
            return false;
        }
        if (defined('DOING_CRON') && DOING_CRON) {
            return false;
        }
        $script = isset($_SERVER['SCRIPT_NAME']) ? (string) $_SERVER['SCRIPT_NAME'] : '';
        if (substr($script, -13) === 'wp-login.php' || substr($script, -11) === 'wp-cron.php') {
            return false;
        }
        // Admin & admin-ajax are observe-only unless the operator opts in — a default
        // that guarantees a wrong baseline can never lock you out of your own site.
        if (is_admin() && self::opt('protect_admin', '0') !== '1') {
            return false;
        }
        return true;
    }

    // ---- hooks ----------------------------------------------------------------

    /** Pre-dispatch gate for normal (non-REST) requests. */
    public static function gate()
    {
        try {
            if (self::$blocked || defined('REST_REQUEST')) {
                return; // REST handled by gate_rest()
            }
            $token = self::token();
            if ($token === '' || !self::enforceable()) {
                return;
            }
            list($block, $reason) = NemesisShield::verdict(
                $token, self::method(), self::path(), self::query(), self::authed()
            );
            if ($block) {
                self::$blocked = true;
                self::deny($reason);
            }
        } catch (\Throwable $e) {
            // fail-open: never let the shield break the site
        }
    }

    /** Pre-dispatch gate for the REST API. Returns a 403 WP_Error to short-circuit. */
    public static function gate_rest($result, $server, $request)
    {
        try {
            if (!empty($result)) {
                return $result; // something already handled it
            }
            $token = self::token();
            if ($token === '' || !self::enforceable()) {
                return $result;
            }
            $path   = method_exists($request, 'get_route') ? '/wp-json' . $request->get_route() : self::path();
            $method = method_exists($request, 'get_method') ? $request->get_method() : self::method();
            $query  = method_exists($request, 'get_query_params') ? (array) $request->get_query_params() : self::query();
            list($block, $reason) = NemesisShield::verdict($token, $method, $path, $query, self::authed());
            if ($block) {
                self::$blocked = true;
                return new WP_Error(
                    'blocked_by_nemesis_shield',
                    is_string($reason) ? $reason : 'off-baseline: unapproved behavior',
                    array('status' => 403)
                );
            }
        } catch (\Throwable $e) {
            // fail-open
        }
        return $result;
    }

    /** Post-response: record the observed behaviour (builds the baseline). */
    public static function observe()
    {
        try {
            $token = self::token();
            if ($token === '' || self::$blocked) {
                return; // a blocked request already recorded its 403 sketch
            }
            if (defined('WP_CLI') && WP_CLI) {
                return;
            }
            $status = function_exists('http_response_code') ? (http_response_code() ?: 200) : 200;
            NemesisShield::observe($token, self::method(), self::path(), self::query(), self::authed(), $status);
        } catch (\Throwable $e) {
            // fail-open
        }
    }

    private static function query()
    {
        return isset($_GET) && is_array($_GET) ? $_GET : array();
    }

    /** Emit the 403 and stop, matching the SDK's raw-PHP guard() contract. */
    private static function deny($reason)
    {
        if (!headers_sent()) {
            status_header(403);
            header('Content-Type: application/json; charset=utf-8');
            nocache_headers();
        }
        echo wp_json_encode(array(
            'error'  => 'blocked_by_nemesis_shield',
            'reason' => is_string($reason) ? $reason : 'off-baseline: unapproved behavior',
        ));
        exit;
    }

    // ---- settings UI ----------------------------------------------------------

    public static function menu()
    {
        add_options_page(
            'Nemesis Shield', 'Nemesis Shield', 'manage_options', 'nemesis-shield',
            array(__CLASS__, 'render_settings')
        );
    }

    public static function register_settings()
    {
        register_setting('nemesis_shield', self::OPT, array(__CLASS__, 'sanitize'));
    }

    public static function sanitize($input)
    {
        $out = self::options();
        $out['token']         = isset($input['token']) ? sanitize_text_field($input['token']) : '';
        $out['endpoint']      = isset($input['endpoint']) ? esc_url_raw(trim($input['endpoint'])) : '';
        $out['protect_admin'] = (isset($input['protect_admin']) && $input['protect_admin'] === '1') ? '1' : '0';
        return $out;
    }

    public static function render_settings()
    {
        if (!current_user_can('manage_options')) {
            return;
        }
        $token_from_env = (defined('NEMESIS_SHIELD_TOKEN') && NEMESIS_SHIELD_TOKEN)
            || ((getenv('NEMESIS_TOKEN') !== false) && getenv('NEMESIS_TOKEN') !== '');
        ?>
        <div class="wrap">
            <h1>Nemesis Shield</h1>
            <p>Positive-security runtime protection. Traffic builds a per-site baseline in
               <strong>observe</strong> mode; approve behaviours in the
               <a href="https://shield.nemesislabs.xyz" target="_blank" rel="noopener">Shield console</a>,
               then flip the app to <strong>enforce</strong> and off-baseline requests are blocked with
               <code>403 blocked_by_nemesis_shield</code>. No redeploy — the mode is pulled live.</p>
            <form method="post" action="options.php">
                <?php settings_fields('nemesis_shield'); ?>
                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row"><label for="ns_token">Install token</label></th>
                        <td>
                            <input name="<?php echo esc_attr(self::OPT); ?>[token]" id="ns_token" type="text"
                                   class="regular-text" value="<?php echo esc_attr(self::opt('token', '')); ?>"
                                   placeholder="nsk_…" autocomplete="off" <?php disabled($token_from_env); ?> />
                            <p class="description">
                                <?php if ($token_from_env): ?>
                                    Provided via the <code>NEMESIS_SHIELD_TOKEN</code> constant / <code>NEMESIS_TOKEN</code> env — this field is ignored.
                                <?php else: ?>
                                    From <a href="https://shield.nemesislabs.xyz" target="_blank" rel="noopener">Protect an app</a>. Prefer setting <code>NEMESIS_SHIELD_TOKEN</code> in <code>wp-config.php</code> to keep it out of the database.
                                <?php endif; ?>
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Protect wp-admin</th>
                        <td>
                            <label>
                                <input type="checkbox" name="<?php echo esc_attr(self::OPT); ?>[protect_admin]" value="1"
                                       <?php checked(self::opt('protect_admin', '0'), '1'); ?> />
                                Also enforce inside wp-admin and admin-ajax
                            </label>
                            <p class="description">Off by default so a still-learning baseline can never lock you out of your own dashboard. Login and cron are never blocked.</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="ns_endpoint">Endpoint (advanced)</label></th>
                        <td>
                            <input name="<?php echo esc_attr(self::OPT); ?>[endpoint]" id="ns_endpoint" type="url"
                                   class="regular-text" value="<?php echo esc_attr(self::opt('endpoint', '')); ?>"
                                   placeholder="https://shield.nemesislabs.xyz/api/v1/sketches" autocomplete="off" />
                            <p class="description">Leave blank for Nemesis Shield cloud. Set only for a self-hosted / on-prem Shield.</p>
                        </td>
                    </tr>
                </table>
                <?php submit_button(); ?>
            </form>
        </div>
        <?php
    }
}

Nemesis_Shield_Plugin::boot();

/**
 * LLM Guard helper for AI features / chatbot plugins. Wrap the user prompt before
 * you send it to a model. Returns the SDK verdict array
 * (['blocked'=>bool,'severity'=>,'kind'=>,'score'=>,'owasp'=>]).
 *
 *   $v = nemesis_shield_guard_llm($prompt, true); // enforce
 *   if ($v['blocked']) { return; } // refuse the prompt
 */
function nemesis_shield_guard_llm($prompt, $enforce = false)
{
    try {
        return NemesisShieldLLM::guardLLM((string) $prompt, (bool) $enforce);
    } catch (\Throwable $e) {
        return array('blocked' => false, 'severity' => 'none', 'score' => 0.0);
    }
}
