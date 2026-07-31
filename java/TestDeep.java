// Deep coverage test for the Java SDK core — proves it SEES an attacker's request from ANY route and
// blocks it in enforce mode (unknown paths, injected/extra params, param-kind / method / auth
// anomalies, knownBad), plus the safe-unlock and fail-open. Mirrors the filter's block logic.
// Compile+run:  javac NemesisShield.java TestDeep.java && java TestDeep
import java.lang.reflect.Field;
import java.util.Map;

public class TestDeep {
    static int pass = 0, fail = 0;
    static void ok(boolean c, String m) {
        if (c) { pass++; System.out.println("  [32m✓[0m " + m); }
        else   { fail++; System.out.println("  [31m✗ " + m + "[0m"); }
    }

    @SuppressWarnings("unchecked")
    static NemesisShield client(String mode, String[] allow, String[] knownBad) throws Exception {
        NemesisShield ns = new NemesisShield(""); // empty token -> no poller, no network
        set(ns, "mode", mode);
        Field sf = NemesisShield.class.getDeclaredField("shapes"); sf.setAccessible(true);
        Map<String, String> shapes = (Map<String, String>) sf.get(ns);
        for (String s : allow) shapes.put(s, "allow");
        Field kf = NemesisShield.class.getDeclaredField("knownBad"); kf.setAccessible(true);
        Map<String, Boolean> kb = (Map<String, Boolean>) kf.get(ns);
        for (String s : knownBad) kb.put(s, true);
        set(ns, "haveBaseline", allow.length > 0 || knownBad.length > 0);
        return ns;
    }
    static void set(Object o, String name, Object v) throws Exception {
        Field f = o.getClass().getDeclaredField(name); f.setAccessible(true); f.set(o, v);
    }

    static String[] split(String url) { // "/p?q=x" -> {"/p","q=x"}
        int i = url.indexOf('?');
        return i < 0 ? new String[]{url, null} : new String[]{url.substring(0, i), url.substring(i + 1)};
    }
    static String shape(NemesisShield ns, String method, String url, boolean authed) {
        String[] pq = split(url);
        return ns.shapeOf(method, pq[0], pq[1], authed);
    }
    // exactly the filter's decision: enforce AND not a bootstrap path AND off-baseline
    static boolean blocked(NemesisShield ns, String method, String url, boolean authed) {
        String[] pq = split(url);
        if (!ns.enforcing() || NemesisShield.neverBlock(pq[0])) return false;
        return ns.decide(ns.shapeOf(method, pq[0], pq[1], authed)) != null;
    }

    public static void main(String[] args) throws Exception {
        NemesisShield ref = new NemesisShield("");
        String[] allow = {
            shape(ref, "GET", "/", false),
            shape(ref, "GET", "/products/12345", false),
            shape(ref, "GET", "/search?q=shoes", false),
            shape(ref, "POST", "/api/orders", true),
        };
        System.out.println("[1mNemesis Shield — Java deep coverage test[0m");

        System.out.println("\n1 · query params change the shape");
        ok(!shape(ref, "GET", "/search?q=x", false).equals(shape(ref, "GET", "/search?q=x&inject=1", false)), "adding a param changes the shape");
        ok(!shape(ref, "GET", "/search?q=shoes", false).equals(shape(ref, "GET", "/search?q=' OR 1=1", false)), "param kind change changes the shape");

        System.out.println("\n2 · enforce — attacks from ANY route blocked, approved passes");
        NemesisShield c = client("enforce", allow, new String[]{});
        ok(!blocked(c, "GET", "/", false), "approved GET / passes");
        ok(!blocked(c, "GET", "/products/999", false), "approved GET /products/{int} passes");
        ok(!blocked(c, "GET", "/search?q=boots", false), "approved GET /search?q=<alnum> passes");
        ok(!blocked(c, "POST", "/api/orders", true), "approved authed POST passes");
        ok(blocked(c, "GET", "/.env", false), "scanner /.env blocked");
        ok(blocked(c, "GET", "/wp-config.php.bak", false), "scanner /wp-config.php.bak blocked");
        ok(blocked(c, "GET", "/search?q=x&cmd=id", false), "injected param blocked");
        ok(blocked(c, "GET", "/search?q=' OR 1=1--", false), "SQLi-shaped param blocked");
        ok(blocked(c, "POST", "/", false), "method anomaly POST / blocked");
        ok(blocked(c, "GET", "/api/orders", false), "auth anomaly (unauth) blocked");
        ok(blocked(c, "GET", "/admin/config", false), "unknown /admin/config blocked");

        System.out.println("\n3 · knownBad (global threat intel)");
        String bad = shape(ref, "POST", "/xmlrpc.php", false);
        ok(blocked(client("enforce", allow, new String[]{bad}), "POST", "/xmlrpc.php", false), "knownBad shape blocked");

        System.out.println("\n4 · safe-unlock — auth path never blocked");
        ok(!blocked(c, "POST", "/login?next=x", false), "/login never blocked");
        ok(!blocked(c, "GET", "/wp-login.php", false), "/wp-login.php never blocked");
        ok(!blocked(c, "GET", "/wp-admin/options.php", false), "/wp-admin never blocked");

        System.out.println("\n5 · fail-open + observe");
        ok(!blocked(client("enforce", new String[]{}, new String[]{}), "GET", "/.env", false), "fail-open with no baseline");
        ok(!blocked(client("observe", allow, new String[]{}), "GET", "/.env", false), "observe mode never blocks");

        System.out.println("\n" + "-".repeat(52));
        if (fail == 0) { System.out.println("[32m[1mALL " + pass + " CHECKS PASSED[0m"); }
        else { System.out.println("[31m[1m" + fail + " FAILED[0m, " + pass + " passed"); System.exit(1); }
    }
}
