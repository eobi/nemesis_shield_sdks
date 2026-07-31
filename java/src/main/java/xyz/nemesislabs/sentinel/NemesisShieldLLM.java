package xyz.nemesislabs.sentinel;

// LLM Guard for Java (JDK 11+, no dependencies) — OWASP-LLM-Top-10 detection with the HashLR ML
// classifier shared across every Nemesis Shield SDK. Feature buckets are fnv1a(feature) % dim,
// identical to every other language; char n-grams over a canonicalized (de-leetspeaked, ASCII-alnum)
// form catch obfuscation the regex layer misses. Weights load from /ml_weights.json on the classpath.

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class NemesisShieldLLM {
    // Feature space (DIM) is fixed across versions; the rest is swappable so refreshModel() can hot-swap
    // a newer published version in place.
    private static int DIM;
    private static double BIAS, BLOCK, FLAG;
    private static int MODEL_VERSION = 1;
    private static final Map<Integer, Double> WEIGHTS = new HashMap<>();
    // Ed25519 public key (hex) that signs published models. Cloud pulls MUST carry a valid signature
    // over the exact bytes; unsigned or tampered bundles are rejected and the embedded model is kept.
    private static final String MODEL_PUBLIC_KEY_HEX = "79d81a3b41966b379a9ba719155b8713f70bb341c3e8fab09fd5563a59893d28";
    private static final Pattern WORD = Pattern.compile("[a-z0-9']+");
    private static final Pattern KV = Pattern.compile("\"(\\d+)\":(-?[0-9.]+)");
    private static final Pattern[] INJECTION = {
        Pattern.compile("ignore\\s+(all\\s+)?(previous|prior|above)\\s+(instructions|prompts?|context)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("disregard\\s+(the\\s+)?(above|previous|system)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(reveal|show|print|repeat)\\s+(your|the)\\s+(system\\s+)?(prompt|instructions)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bDAN\\b|do\\s+anything\\s+now|developer\\s+mode|jailbreak", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(bypass|ignore|disable)\\s+(your\\s+)?(safety|content\\s+policy|guardrails?)", Pattern.CASE_INSENSITIVE),
    };

    static {
        applyModel(readWeights(), true);
    }

    // Parse a HashLR bundle and load it into the live model state. When init==true DIM is set (embedded
    // load); on a refresh DIM is fixed and enforced by the caller.
    private static void applyModel(String json, boolean init) {
        if (init) DIM = (int) longField(json, "dim", 8192);
        BIAS = doubleField(json, "bias", 0);
        BLOCK = doubleField(json, "blockThreshold", 0.85);
        FLAG = doubleField(json, "flagThreshold", 0.45);
        MODEL_VERSION = (int) longField(json, "version", MODEL_VERSION);
        WEIGHTS.clear();
        int wStart = json.indexOf("\"weights\":{");
        if (wStart >= 0) {
            int b = json.indexOf('{', wStart), e = json.indexOf('}', b);
            Matcher m = KV.matcher(json.substring(b, e < 0 ? json.length() : e));
            while (m.find()) WEIGHTS.put(Integer.parseInt(m.group(1)), Double.parseDouble(m.group(2)));
        }
    }

    public static int modelVersion() { return MODEL_VERSION; }

    private static boolean verifyModelSignature(byte[] raw, String sigB64) {
        if (MODEL_PUBLIC_KEY_HEX.isEmpty()) return true;   // no key pinned — version gate + HTTPS apply
        if (sigB64 == null || sigB64.isEmpty()) return false; // key pinned but bundle unsigned — reject
        try {
            byte[] rawKey = hexToBytes(MODEL_PUBLIC_KEY_HEX);
            // wrap the 32 raw bytes as an X.509 SubjectPublicKeyInfo (RFC 8410 Ed25519 prefix)
            byte[] prefix = hexToBytes("302a300506032b6570032100");
            byte[] der = new byte[prefix.length + rawKey.length];
            System.arraycopy(prefix, 0, der, 0, prefix.length);
            System.arraycopy(rawKey, 0, der, prefix.length, rawKey.length);
            var pub = java.security.KeyFactory.getInstance("Ed25519")
                .generatePublic(new java.security.spec.X509EncodedKeySpec(der));
            var sig = java.security.Signature.getInstance("Ed25519");
            sig.initVerify(pub);
            sig.update(raw);
            return sig.verify(java.util.Base64.getDecoder().decode(sigB64));
        } catch (Exception e) {
            return false;
        }
    }

    private static byte[] hexToBytes(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return out;
    }

    /**
     * Hot-swap the HashLR model from a cloud URL if a newer signed version is published, so the model
     * can be retrained and pushed centrally without redeploying the SDK. Returns the new version number
     * if updated, else null. Fail-safe: on any error the current (embedded) model is kept.
     * URL defaults to env NEMESIS_MODEL_URL.
     */
    public static Integer refreshModel(String url) {
        if (url == null) url = System.getenv("NEMESIS_MODEL_URL");
        if (url == null || url.isEmpty()) return null;
        try {
            var client = java.net.http.HttpClient.newBuilder()
                .connectTimeout(java.time.Duration.ofSeconds(5)).build();
            var req = java.net.http.HttpRequest.newBuilder(java.net.URI.create(url))
                .timeout(java.time.Duration.ofSeconds(5)).GET().build();
            var resp = client.send(req, java.net.http.HttpResponse.BodyHandlers.ofByteArray());
            if (resp.statusCode() != 200) return null;
            byte[] raw = resp.body();
            String sig = resp.headers().firstValue("x-model-signature").orElse(null);
            if (!verifyModelSignature(raw, sig)) return null; // integrity gate
            String json = new String(raw, StandardCharsets.UTF_8);
            int newVer = (int) longField(json, "version", 0);
            int newDim = (int) longField(json, "dim", DIM);
            if (newVer <= MODEL_VERSION || newDim != DIM) return null; // version / dim gate
            applyModel(json, false);
            return MODEL_VERSION;
        } catch (Exception e) {
            return null;
        }
    }

    private static String readWeights() {
        try (var is = NemesisShieldLLM.class.getResourceAsStream("/ml_weights.json")) {
            if (is != null) return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        } catch (Exception ignored) {}
        try { return Files.readString(Path.of("ml_weights.json")); } catch (Exception e) { return "{}"; }
    }

    private static long longField(String j, String k, long dflt) {
        Matcher m = Pattern.compile("\"" + k + "\":(-?[0-9]+)").matcher(j);
        return m.find() ? Long.parseLong(m.group(1)) : dflt;
    }

    private static double doubleField(String j, String k, double dflt) {
        Matcher m = Pattern.compile("\"" + k + "\":(-?[0-9.]+)").matcher(j);
        return m.find() ? Double.parseDouble(m.group(1)) : dflt;
    }

    private static long fnv1a(String s) {
        long h = 0x811c9dc5L;
        for (int i = 0; i < s.length(); i++) {
            h ^= (s.charAt(i) & 0xff);
            h = (h * 0x01000193L) & 0xffffffffL;
        }
        return h;
    }

    private static int bucket(String s) {
        return (int) (fnv1a(s) % DIM);
    }

    private static char leet(char c) {
        switch (c) {
            case '0': return 'o'; case '1': return 'i'; case '3': return 'e'; case '4': return 'a';
            case '5': return 's'; case '7': return 't'; case '@': return 'a'; case '$': return 's';
            case '8': return 'b'; case '|': return 'i'; default: return c;
        }
    }

    private static String canon(String text) {
        String t = text.toLowerCase();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < t.length(); i++) {
            char c = leet(t.charAt(i));
            if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) sb.append(c);
        }
        return sb.toString();
    }

    private static Set<Integer> features(String text) {
        Set<Integer> b = new HashSet<>();
        Matcher m = WORD.matcher(text.toLowerCase());
        java.util.List<String> ws = new java.util.ArrayList<>();
        while (m.find()) ws.add(m.group());
        for (String w : ws) b.add(bucket("w:" + w));
        for (int i = 0; i + 1 < ws.size(); i++) b.add(bucket("b:" + ws.get(i) + " " + ws.get(i + 1)));
        String c = canon(text);
        for (int n : new int[]{3, 4, 5})
            for (int i = 0; i + n <= c.length(); i++) b.add(bucket("c" + n + ":" + c.substring(i, i + n)));
        if (text.length() > 2000) b.add(bucket("e:long"));
        int na = 0;
        for (int i = 0; i < text.length(); i++) if (text.charAt(i) > 127) na++;
        if (na > 3) b.add(bucket("e:nonascii"));
        return b;
    }

    /** Probability (0..1) that {@code text} is a prompt-injection / jailbreak attempt. */
    public static double mlInjectionScore(String text) {
        double z = BIAS;
        for (int bk : features(text)) { Double w = WEIGHTS.get(bk); if (w != null) z += w; }
        if (z < -30) return 0;
        if (z > 30) return 1;
        return 1.0 / (1.0 + Math.exp(-z));
    }

    /** Verdict for one guarded prompt. */
    public static final class Verdict {
        public final boolean blocked; public final String severity, kind, owasp; public final double score;
        Verdict(boolean b, String sev, String k, double s, String o) { blocked = b; severity = sev; kind = k; score = s; owasp = o; }
    }

    /** Regex rules first, then HashLR ML for obfuscation. {@code enforce} gates blocking. */
    public static Verdict guardLLM(String prompt, boolean enforce) {
        for (Pattern re : INJECTION)
            if (re.matcher(prompt).find())
                return new Verdict(enforce, "high", "prompt_injection", 1.0, "LLM01");
        double s = mlInjectionScore(prompt);
        if (s >= BLOCK) return new Verdict(enforce, "high", "ml_prompt_injection", s, "LLM01");
        if (s >= FLAG) return new Verdict(false, "medium", "ml_prompt_injection", s, "LLM01");
        return new Verdict(false, "none", "", s, "");
    }
}
