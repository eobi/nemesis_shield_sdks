<?php
/**
 * Plugin Name:       Nemesis Shield
 * Plugin URI:        https://shield.nemesislabs.xyz
 * Description:       Connects your site to the Nemesis Shield service for positive-security runtime protection. The service learns your site's normal behaviour and, in enforce mode, tells the plugin to block off-baseline requests (auth bypass, path traversal, scanners, unusual methods). Privacy-preserving, fail-open.
 * Version:           1.0.0
 * Requires at least: 5.9
 * Requires PHP:      7.2
 * Author:            Nemesis Labs
 * Author URI:        https://nemesislabs.xyz
 * License:           MIT
 * License URI:       https://opensource.org/licenses/MIT
 * Text Domain:       nemesis-shield
 *
 * Nemesis Shield is a client for an external service (see readme.txt for the data-and-privacy
 * disclosure). It computes a privacy-preserving *shape* of each request locally (method + path shape +
 * param kinds + auth flag, never bodies, values, or secrets), sends those shapes to the service, caches
 * the compiled policy the service returns, and applies the service's decision in-process. Observe →
 * approve in the console → enforce. Fail-open: if the service is unreachable, the site is unaffected.
 * WordPress admin, login and cron are never blocked unless you opt in.
 *
 * @package Nemesis_Shield
 */

if (!defined('ABSPATH')) {
    exit; // no direct access
}

require_once __DIR__ . '/lib/NemesisShieldWP.php';
require_once __DIR__ . '/lib/NemesisShieldLLM.php';
require_once __DIR__ . '/lib/class-login-guard.php';

final class Nemesis_Shield_Plugin
{
    const OPT = 'nemesis_shield_options';
    const VERSION = '1.0.0';

    /** Cache the resolved token so we don't recompute it on every hook. */
    private static $token = null;
    private static $blocked = false; // guard against double-blocking within one request

    public static function boot()
    {
        // Let a wp-config constant / settings value point the plugin at a self-hosted service.
        $ep = self::opt('endpoint', '');
        if ($ep !== '' && !defined('NEMESIS_SHIELD_ENDPOINT')) {
            define('NEMESIS_SHIELD_ENDPOINT', $ep);
        }

        // Gate: run as early as auth state is reliable. On `init` is_user_logged_in() works, and it
        // fires for the front end, wp-admin, and admin-ajax alike, before the main query / template.
        add_action('init', array(__CLASS__, 'gate'), PHP_INT_MIN);

        // REST gets its own pre-dispatch gate so we can block with a proper JSON 403 before the route
        // handler runs, with REST auth already resolved.
        add_filter('rest_pre_dispatch', array(__CLASS__, 'gate_rest'), PHP_INT_MIN, 3);

        // Observe every request at the very end, once the status code exists.
        add_action('shutdown', array(__CLASS__, 'observe'), PHP_INT_MAX);

        // Complement: brute-force login protection (behavioral shaping can't see brute force, since a
        // malicious login has the same shape as a real one).
        Nemesis_Shield_Login_Guard::init();

        if (is_admin()) {
            add_action('admin_menu', array(__CLASS__, 'menu'));
            add_action('admin_init', array(__CLASS__, 'register_settings'));
            add_action('admin_post_nemesis_shield_unlock', array(__CLASS__, 'handle_unlock'));
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
     * Token precedence: NEMESIS_SHIELD_TOKEN constant (wp-config) > NEMESIS_TOKEN env > the value saved
     * in Settings. Constants/env keep the secret out of the database.
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

    // ---- request extraction (all superglobal reads unslashed + sanitized) -----

    private static function method()
    {
        return isset($_SERVER['REQUEST_METHOD'])
            ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_METHOD']))
            : 'GET';
    }

    private static function path()
    {
        $uri = isset($_SERVER['REQUEST_URI'])
            ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI']))
            : '/';
        return '/' . ltrim(strtok($uri, '?'), '/');
    }

    private static function authed()
    {
        if (function_exists('is_user_logged_in') && is_user_logged_in()) {
            return true;
        }
        // API callers (application passwords, bearer/basic) show up as headers. Apache's common
        // "pass the Authorization header" rewrite sets these to an EMPTY string on anonymous requests,
        // so test for a non-empty value, not mere presence, or every visitor would be mislabelled
        // authenticated and poison the baseline.
        $h = '';
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $h = sanitize_text_field(wp_unslash($_SERVER['HTTP_AUTHORIZATION']));
        } elseif (isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) {
            $h = sanitize_text_field(wp_unslash($_SERVER['REDIRECT_HTTP_AUTHORIZATION']));
        }
        return $h !== '';
    }

    /**
     * The query parameters, unslashed and sanitized. Only the parameter NAMES and value KINDS shape
     * the request signature, so scalar values are sanitized and arrays reduced to sanitized scalars.
     * No nonce applies: this is a read-only request gate, not form processing.
     */
    private static function query()
    {
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only positive-security request gate, not form processing.
        if (empty($_GET) || !is_array($_GET)) {
            return array();
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only positive-security request gate, not form processing.
        $raw = wp_unslash($_GET);
        return self::shapeParams($raw);
    }

    /**
     * The POST body parameters, unslashed and reduced to NAMES + value KINDS (never values). This is
     * what makes state-changing WordPress requests (settings saves, post edits, comments, WooCommerce,
     * plugin forms) have a real signature instead of collapsing to a bare "POST /path".
     * No nonce applies: this is a read-only request gate that inspects the request's structure, not a
     * form handler acting on the data.
     */
    private static function post()
    {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- read-only positive-security request gate, not form processing.
        if (empty($_POST) || !is_array($_POST)) {
            return array();
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- read-only positive-security request gate, not form processing.
        $raw = wp_unslash($_POST);
        return self::shapeParams($raw);
    }

    /** Sanitize a superglobal array into name => scalar/array-of-scalars for shape computation. */
    private static function shapeParams($raw)
    {
        $out = array();
        foreach ($raw as $k => $v) {
            $key = sanitize_text_field((string) $k);
            if (is_array($v)) {
                $out[$key] = array_map('sanitize_text_field', array_map('strval', $v));
            } else {
                $out[$key] = sanitize_text_field((string) $v);
            }
        }
        return $out;
    }

    /** The request's parameters (query + body) as names + kinds, for the shape. Body names win on collision. */
    private static function params()
    {
        return array_merge(self::query(), self::post());
    }

    /**
     * WordPress routes a large share of functionality through wp-admin/admin-ajax.php and admin-post.php
     * with an `action` selector (in GET or POST). That selector IS the effective endpoint, so we fold it
     * into the route (as a routing identifier, like a path segment) to give each action its own shape.
     * `action` values are registered hook names, not user data. Returns '' when there is no action.
     */
    private static function ajaxAction()
    {
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- reads only the routing selector, not acted-on data.
        if (!isset($_REQUEST['action'])) {
            return '';
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- reads only the routing selector, not acted-on data.
        $a = sanitize_key(wp_unslash($_REQUEST['action']));
        return strlen($a) > 64 ? substr($a, 0, 64) : $a;
    }

    /**
     * The path used for shaping. For admin-ajax.php / admin-post.php the `action` selector is folded in
     * so distinct actions are distinct shapes (a heartbeat and a user-delete are no longer the same).
     */
    private static function effectivePath()
    {
        $path = self::path();
        $lc = strtolower($path);
        if (substr($lc, -14) === 'admin-ajax.php' || substr($lc, -15) === 'admin-post.php') {
            $a = self::ajaxAction();
            if ($a !== '') {
                $path = rtrim($path, '/') . '/' . $a;
            }
        }
        return $path;
    }

    /**
     * REST request parameters for the shape: query params plus the body/JSON param NAMES (their value
     * KINDS are derived but values are never sent). WordPress has already parsed and slash-handled these
     * on the request object, so no extra unslashing is needed.
     */
    private static function restParams($request)
    {
        if (!is_object($request)) {
            return self::params();
        }
        $merged = array();
        foreach (array('get_query_params', 'get_body_params', 'get_json_params') as $m) {
            if (method_exists($request, $m)) {
                $p = $request->$m();
                if (is_array($p)) {
                    $merged = array_merge($merged, $p);
                }
            }
        }
        return $merged;
    }

    /**
     * Whether we should *enforce* (block) on this request. Observation always runs; blocking is held
     * back on the surfaces that could lock an operator out unless they explicitly opt in. Login and
     * cron are never blocked; WP-CLI is exempt.
     */
    private static function enforceable()
    {
        if (defined('WP_CLI') && WP_CLI) {
            return false;
        }
        if (defined('DOING_CRON') && DOING_CRON) {
            return false;
        }
        $script = isset($_SERVER['SCRIPT_NAME'])
            ? sanitize_text_field(wp_unslash($_SERVER['SCRIPT_NAME']))
            : '';
        if (substr($script, -13) === 'wp-login.php' || substr($script, -11) === 'wp-cron.php') {
            return false;
        }
        if (is_admin()) {
            // Admin context. Regular wp-admin PAGE loads are ALWAYS observe-only so a wrong baseline can
            // never lock you out of your dashboard (including this plugin's own settings page). Only the
            // admin-ajax / admin-post APIs are enforceable, and only when "Protect wp-admin" is on.
            if (self::opt('protect_admin', '0') !== '1') {
                return false;
            }
            $lc = strtolower(self::path());
            $is_api = (substr($lc, -14) === 'admin-ajax.php' || substr($lc, -14) === 'admin-post.php');
            return $is_api;
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
            list($block, $reason) = NemesisShieldWP::verdict(
                $token, self::method(), self::effectivePath(), self::params(), self::authed()
            );
            if ($block) {
                self::$blocked = true;
                self::deny($reason);
            }
        } catch (\Throwable $e) {
            // fail-open: never let the shield break the site
            unset($e);
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
            $path   = (is_object($request) && method_exists($request, 'get_route')) ? '/wp-json' . $request->get_route() : self::path();
            $method = (is_object($request) && method_exists($request, 'get_method')) ? $request->get_method() : self::method();
            // Shape includes the REST body's parameter names + kinds (never values), so a POST/PUT/PATCH
            // write to an endpoint is distinguished by its payload structure, not just its route.
            $query  = self::restParams($request);
            list($block, $reason) = NemesisShieldWP::verdict($token, $method, $path, $query, self::authed());
            if ($block) {
                self::$blocked = true;
                return new WP_Error(
                    'blocked_by_nemesis_shield',
                    is_string($reason) ? $reason : 'off-baseline: unapproved behavior',
                    array('status' => 403)
                );
            }
        } catch (\Throwable $e) {
            unset($e); // fail-open
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
            NemesisShieldWP::observe($token, self::method(), self::effectivePath(), self::params(), self::authed(), $status);
        } catch (\Throwable $e) {
            unset($e); // fail-open
        }
    }

    /** Emit the 403 and stop. */
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
            'Nemesis Shield',
            'Nemesis Shield',
            'manage_options',
            'nemesis-shield',
            array(__CLASS__, 'render_settings')
        );
    }

    public static function register_settings()
    {
        register_setting('nemesis_shield', self::OPT, array('sanitize_callback' => array(__CLASS__, 'sanitize')));
    }

    public static function sanitize($input)
    {
        $out = self::options();
        $out['token']         = isset($input['token']) ? sanitize_text_field($input['token']) : '';
        $out['endpoint']      = isset($input['endpoint']) ? esc_url_raw(trim($input['endpoint'])) : '';
        $out['protect_admin'] = (isset($input['protect_admin']) && $input['protect_admin'] === '1') ? '1' : '0';
        // Brute-force login protection.
        $out['login_guard']   = (isset($input['login_guard']) && $input['login_guard'] === '1') ? '1' : '0';
        $out['lg_max']        = isset($input['lg_max']) ? max(1, (int) $input['lg_max']) : 5;
        $out['lg_window']     = isset($input['lg_window']) ? max(60, (int) $input['lg_window']) : 900;
        $out['lg_lockout']    = isset($input['lg_lockout']) ? max(60, (int) $input['lg_lockout']) : 1800;
        return $out;
    }

    public static function render_settings()
    {
        if (!current_user_can('manage_options')) {
            return;
        }
        $token_from_env = (defined('NEMESIS_SHIELD_TOKEN') && NEMESIS_SHIELD_TOKEN)
            || ((getenv('NEMESIS_TOKEN') !== false) && getenv('NEMESIS_TOKEN') !== '');
        $allowed = array('strong' => array(), 'code' => array(), 'a' => array('href' => array(), 'target' => array(), 'rel' => array()));
        ?>
        <div class="wrap">
            <h1><?php echo esc_html__('Nemesis Shield', 'nemesis-shield'); ?></h1>
            <p><?php echo wp_kses(
                __('Positive-security runtime protection powered by the <a href="https://shield.nemesislabs.xyz" target="_blank" rel="noopener">Nemesis Shield service</a>. Your traffic builds a per-site baseline in <strong>observe</strong> mode; you approve behaviours in the console, then set the app to <strong>enforce</strong> and off-baseline requests are blocked with <code>403 blocked_by_nemesis_shield</code>. No redeploy. The mode is pulled live.', 'nemesis-shield'),
                $allowed
            ); ?></p>
            <form method="post" action="options.php">
                <?php settings_fields('nemesis_shield'); ?>
                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row"><label for="ns_token"><?php echo esc_html__('Install token', 'nemesis-shield'); ?></label></th>
                        <td>
                            <input name="<?php echo esc_attr(self::OPT); ?>[token]" id="ns_token" type="text"
                                   class="regular-text" value="<?php echo esc_attr(self::opt('token', '')); ?>"
                                   placeholder="nsk_..." autocomplete="off" <?php disabled($token_from_env); ?> />
                            <p class="description">
                                <?php if ($token_from_env) : ?>
                                    <?php echo wp_kses(__('Provided via the <code>NEMESIS_SHIELD_TOKEN</code> constant / <code>NEMESIS_TOKEN</code> environment variable, so this field is ignored.', 'nemesis-shield'), $allowed); ?>
                                <?php else : ?>
                                    <?php echo wp_kses(__('From <a href="https://shield.nemesislabs.xyz" target="_blank" rel="noopener">Protect an app</a> in the Nemesis Shield console. Prefer setting <code>NEMESIS_SHIELD_TOKEN</code> in <code>wp-config.php</code> to keep it out of the database.', 'nemesis-shield'), $allowed); ?>
                                <?php endif; ?>
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php echo esc_html__('Protect wp-admin', 'nemesis-shield'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="<?php echo esc_attr(self::OPT); ?>[protect_admin]" value="1"
                                       <?php checked(self::opt('protect_admin', '0'), '1'); ?> />
                                <?php echo esc_html__('Also enforce the admin-ajax and admin-post APIs', 'nemesis-shield'); ?>
                            </label>
                            <p class="description"><?php echo esc_html__('Off by default. When on, off-baseline admin-ajax / admin-post actions are blocked. Regular wp-admin page loads are always observe-only, so a still-learning baseline can never lock you out of your dashboard or this settings page. Login and cron are never blocked.', 'nemesis-shield'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="ns_endpoint"><?php echo esc_html__('Endpoint (advanced)', 'nemesis-shield'); ?></label></th>
                        <td>
                            <input name="<?php echo esc_attr(self::OPT); ?>[endpoint]" id="ns_endpoint" type="url"
                                   class="regular-text" value="<?php echo esc_attr(self::opt('endpoint', '')); ?>"
                                   placeholder="https://shield.nemesislabs.xyz/api/v1/sketches" autocomplete="off" />
                            <p class="description"><?php echo esc_html__('Leave blank for the Nemesis Shield cloud. Set only for a self-hosted service.', 'nemesis-shield'); ?></p>
                        </td>
                    </tr>
                    <tr><th colspan="2"><h2 style="margin:8px 0 0"><?php echo esc_html__('Login protection', 'nemesis-shield'); ?></h2>
                        <p class="description" style="font-weight:400"><?php echo esc_html__('Brute-force lockout. Complements the behavioral shield, which cannot see brute force because a malicious login has the same shape as a real one.', 'nemesis-shield'); ?></p></th></tr>
                    <tr>
                        <th scope="row"><?php echo esc_html__('Brute-force lockout', 'nemesis-shield'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="<?php echo esc_attr(self::OPT); ?>[login_guard]" value="1"
                                       <?php checked(self::opt('login_guard', '1'), '1'); ?> />
                                <?php echo esc_html__('Lock out an IP after too many failed logins', 'nemesis-shield'); ?>
                            </label>
                            <p class="description"><?php echo esc_html__('Covers wp-login, XML-RPC and application-password auth. Lockouts auto-expire; login is never permanently blocked.', 'nemesis-shield'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="ns_lg_max"><?php echo esc_html__('Failed attempts before lockout', 'nemesis-shield'); ?></label></th>
                        <td><input name="<?php echo esc_attr(self::OPT); ?>[lg_max]" id="ns_lg_max" type="number" min="1" class="small-text" value="<?php echo esc_attr((string) self::opt('lg_max', 5)); ?>" /></td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="ns_lg_window"><?php echo esc_html__('Counting window (seconds)', 'nemesis-shield'); ?></label></th>
                        <td><input name="<?php echo esc_attr(self::OPT); ?>[lg_window]" id="ns_lg_window" type="number" min="60" class="small-text" value="<?php echo esc_attr((string) self::opt('lg_window', 900)); ?>" /></td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="ns_lg_lockout"><?php echo esc_html__('Lockout duration (seconds)', 'nemesis-shield'); ?></label></th>
                        <td><input name="<?php echo esc_attr(self::OPT); ?>[lg_lockout]" id="ns_lg_lockout" type="number" min="60" class="small-text" value="<?php echo esc_attr((string) self::opt('lg_lockout', 1800)); ?>" /></td>
                    </tr>
                </table>
                <?php submit_button(); ?>
            </form>
            <?php self::render_lockouts(); ?>
        </div>
        <?php
    }

    /** Active lockouts, with a nonce-protected unlock link for each. */
    public static function render_lockouts()
    {
        $locks = Nemesis_Shield_Login_Guard::active_lockouts();
        echo '<h2>' . esc_html__('Active login lockouts', 'nemesis-shield') . '</h2>';
        if (empty($locks)) {
            echo '<p class="description">' . esc_html__('No IPs are currently locked out.', 'nemesis-shield') . '</p>';
            return;
        }
        echo '<table class="widefat striped" style="max-width:640px"><thead><tr>';
        echo '<th>' . esc_html__('IP address', 'nemesis-shield') . '</th>';
        echo '<th>' . esc_html__('Locked until (UTC)', 'nemesis-shield') . '</th>';
        echo '<th></th></tr></thead><tbody>';
        foreach ($locks as $rec) {
            $ip = (string) ($rec['ip'] ?? '');
            $until = (int) ($rec['until'] ?? 0);
            $url = wp_nonce_url(
                admin_url('admin-post.php?action=nemesis_shield_unlock&ip=' . rawurlencode($ip)),
                'nemesis_shield_unlock_' . $ip
            );
            echo '<tr><td><code>' . esc_html($ip) . '</code></td>';
            echo '<td>' . esc_html(gmdate('Y-m-d H:i:s', $until)) . '</td>';
            echo '<td><a class="button button-small" href="' . esc_url($url) . '">' . esc_html__('Unlock', 'nemesis-shield') . '</a></td></tr>';
        }
        echo '</tbody></table>';
    }

    /** Handle the unlock action: capability + nonce checked, IP sanitized. */
    public static function handle_unlock()
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You are not allowed to do this.', 'nemesis-shield'));
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- the IP is read only to build the nonce action; the nonce is verified on the very next line.
        $ip = isset($_GET['ip']) ? sanitize_text_field(wp_unslash($_GET['ip'])) : '';
        check_admin_referer('nemesis_shield_unlock_' . $ip);
        if ($ip !== '') {
            Nemesis_Shield_Login_Guard::admin_unlock($ip);
        }
        wp_safe_redirect(admin_url('options-general.php?page=nemesis-shield'));
        exit;
    }
}

Nemesis_Shield_Plugin::boot();

/**
 * LLM Guard helper for AI features / chatbot plugins. Wrap the user prompt before you send it to a
 * model. Returns the classifier verdict array (array('blocked'=>bool,'severity'=>,'kind'=>,'score'=>,'owasp'=>)).
 *
 *   $v = nemesis_shield_guard_llm( $prompt, true ); // enforce
 *   if ( $v['blocked'] ) { return; } // refuse the prompt
 *
 * @param string $prompt  The user prompt to classify.
 * @param bool   $enforce Whether a high-risk prompt should be marked blocked.
 * @return array
 */
function nemesis_shield_guard_llm($prompt, $enforce = false)
{
    try {
        return NemesisShieldLLM::guardLLM((string) $prompt, (bool) $enforce);
    } catch (\Throwable $e) {
        unset($e);
        return array('blocked' => false, 'severity' => 'none', 'score' => 0.0);
    }
}
