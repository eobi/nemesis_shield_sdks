<?php
/**
 * Nemesis Shield: vulnerability awareness.
 *
 * A complement to the behavioral shield. Behavioral protection blocks *exploitation* of a vulnerable
 * component (the exploit request is off-baseline) even before you patch, but it can't *tell you* the
 * vulnerability exists. This module surfaces risk from your installed inventory two ways:
 *
 *   1. Local, no account: components with an available update, or that were removed from the
 *      WordPress.org directory (a strong abandonment/security signal). Uses WordPress's own cached
 *      update data, so no extra network calls.
 *   2. Service-fed (when connected): the installed plugin/theme inventory is sent to the Nemesis
 *      service, which returns known CVE advisories. Degrades gracefully when no token is set or the
 *      endpoint is unavailable.
 *
 * @package Nemesis_Shield
 */

if (!defined('ABSPATH')) {
    exit;
}

class Nemesis_Shield_Vulns
{
    const CACHE = 'nemesis_shield_vulns';   // option: cached service advisories
    const CRON = 'nemesis_shield_daily_vulns';

    public static function schedule()
    {
        if (!wp_next_scheduled(self::CRON)) {
            wp_schedule_event(time() + 600, 'daily', self::CRON);
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
        add_action(self::CRON, array(__CLASS__, 'refresh'));
    }

    /** Installed plugins + themes as array of array(type, id, name, version). */
    public static function inventory()
    {
        $out = array();
        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        foreach (get_plugins() as $file => $p) {
            $out[] = array(
                'type'    => 'plugin',
                'id'      => dirname($file) !== '.' ? dirname($file) : $file,
                'name'    => (string) ($p['Name'] ?? $file),
                'version' => (string) ($p['Version'] ?? ''),
            );
        }
        if (function_exists('wp_get_themes')) {
            foreach (wp_get_themes() as $slug => $t) {
                $out[] = array(
                    'type'    => 'theme',
                    'id'      => (string) $slug,
                    'name'    => method_exists($t, 'get') ? (string) $t->get('Name') : (string) $slug,
                    'version' => method_exists($t, 'get') ? (string) $t->get('Version') : '',
                );
            }
        }
        return $out;
    }

    /** Components with an available update, from WordPress's own cached update data (no extra HTTP). */
    public static function outdated()
    {
        $out = array();
        if (!function_exists('get_plugin_updates') || !function_exists('get_theme_updates')) {
            require_once ABSPATH . 'wp-admin/includes/update.php';
        }
        if (function_exists('get_plugin_updates')) {
            foreach ((array) get_plugin_updates() as $file => $p) {
                $out[] = array(
                    'type'    => 'plugin',
                    'name'    => (string) ($p->Name ?? $file),
                    'current' => (string) ($p->Version ?? ''),
                    'new'     => isset($p->update->new_version) ? (string) $p->update->new_version : '',
                );
            }
        }
        if (function_exists('get_theme_updates')) {
            foreach ((array) get_theme_updates() as $slug => $t) {
                $new = '';
                if (isset($t->update['new_version'])) {
                    $new = (string) $t->update['new_version'];
                }
                $out[] = array(
                    'type'    => 'theme',
                    'name'    => method_exists($t, 'get') ? (string) $t->get('Name') : (string) $slug,
                    'current' => method_exists($t, 'get') ? (string) $t->get('Version') : '',
                    'new'     => $new,
                );
            }
        }
        return $out;
    }

    private static function token()
    {
        if (defined('NEMESIS_SHIELD_TOKEN') && NEMESIS_SHIELD_TOKEN) {
            return (string) NEMESIS_SHIELD_TOKEN;
        }
        if (($env = getenv('NEMESIS_TOKEN')) !== false && $env !== '') {
            return (string) $env;
        }
        $o = get_option('nemesis_shield_options', array());
        return is_array($o) ? (string) ($o['token'] ?? '') : '';
    }

    private static function endpoint()
    {
        if (defined('NEMESIS_SHIELD_VULN_ENDPOINT') && NEMESIS_SHIELD_VULN_ENDPOINT) {
            return NEMESIS_SHIELD_VULN_ENDPOINT;
        }
        if (defined('NEMESIS_SHIELD_ENDPOINT') && NEMESIS_SHIELD_ENDPOINT) {
            return str_replace('/api/v1/sketches', '/api/v1/vulns', NEMESIS_SHIELD_ENDPOINT);
        }
        return 'https://shield.nemesislabs.xyz/api/v1/vulns';
    }

    /**
     * Ask the service for CVE advisories matching the installed inventory. Caches the result.
     * Returns the advisories array (possibly empty). Never throws.
     */
    public static function refresh()
    {
        $token = self::token();
        if ($token === '' || !function_exists('wp_remote_post')) {
            return array();
        }
        $res = wp_remote_post(self::endpoint(), array(
            'headers'  => array('Authorization' => 'Bearer ' . $token, 'Content-Type' => 'application/json'),
            'body'     => wp_json_encode(array('inventory' => self::inventory())),
            'timeout'  => 5,
            'blocking' => true,
        ));
        if (is_wp_error($res)) {
            return self::cached();
        }
        $code = (int) wp_remote_retrieve_response_code($res);
        if ($code < 200 || $code >= 300) {
            return self::cached();
        }
        $body = json_decode(wp_remote_retrieve_body($res), true);
        $advisories = (is_array($body) && isset($body['advisories']) && is_array($body['advisories'])) ? $body['advisories'] : array();
        update_option(self::CACHE, array('ts' => gmdate('Y-m-d H:i:s'), 'advisories' => $advisories), false);
        return $advisories;
    }

    /** Cached service advisories (array), or empty. */
    public static function cached()
    {
        $c = get_option(self::CACHE, array());
        return (is_array($c) && isset($c['advisories']) && is_array($c['advisories'])) ? $c['advisories'] : array();
    }

    public static function cached_at()
    {
        $c = get_option(self::CACHE, array());
        return is_array($c) ? (string) ($c['ts'] ?? '') : '';
    }

    /** Total risk items = service advisories + locally-outdated components. */
    public static function risk_count()
    {
        return count(self::cached()) + count(self::outdated());
    }
}
