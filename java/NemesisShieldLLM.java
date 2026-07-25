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
    private static final int DIM;
    private static final double BIAS, BLOCK, FLAG;
    private static final Map<Integer, Double> WEIGHTS = new HashMap<>();
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
        String json = readWeights();
        DIM = (int) longField(json, "dim", 8192);
        BIAS = doubleField(json, "bias", 0);
        BLOCK = doubleField(json, "blockThreshold", 0.85);
        FLAG = doubleField(json, "flagThreshold", 0.45);
        int wStart = json.indexOf("\"weights\":{");
        if (wStart >= 0) {
            int b = json.indexOf('{', wStart), e = json.indexOf('}', b);
            Matcher m = KV.matcher(json.substring(b, e < 0 ? json.length() : e));
            while (m.find()) WEIGHTS.put(Integer.parseInt(m.group(1)), Double.parseDouble(m.group(2)));
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
