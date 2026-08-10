package io.github.eobi.sentinel;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

/**
 * Cross-SDK byte-parity: NemesisShield.normalizePath MUST reproduce every canonical vector in
 * tokenize.vectors.json ("normalizePath") exactly. Source of truth = packages/shared/src/tokenize.ts.
 */
class TokenizeParityTest {

    // Locate tokenize.vectors.json relative to the java module (repo-root/tokenize.vectors.json).
    private static Path vectorsFile() {
        Path[] candidates = {
            Path.of("../tokenize.vectors.json"),
            Path.of("tokenize.vectors.json"),
            Path.of(System.getProperty("user.dir"), "../tokenize.vectors.json"),
        };
        for (Path p : candidates) if (Files.exists(p)) return p;
        throw new IllegalStateException("tokenize.vectors.json not found from " + System.getProperty("user.dir"));
    }

    @Test
    void normalizePathMatchesCanonicalVectors() throws Exception {
        String json = Files.readString(vectorsFile(), StandardCharsets.UTF_8);
        // Extract each {"path":"..","expect":".."} pair in order. Values carry no quotes/backslashes.
        Matcher m = Pattern.compile("\"path\"\\s*:\\s*\"([^\"]*)\"[^}]*?\"expect\"\\s*:\\s*\"([^\"]*)\"").matcher(json);
        List<String[]> cases = new ArrayList<>();
        while (m.find()) cases.add(new String[] {m.group(1), m.group(2)});

        assertEquals(36, cases.size(), "expected 36 canonical vectors");

        List<String> failures = new ArrayList<>();
        for (String[] c : cases) {
            String path = c[0], expect = c[1];
            String got = NemesisShield.normalizePath(path);
            if (!expect.equals(got)) failures.add("  path=" + path + "  expect=" + expect + "  got=" + got);
        }
        int passed = cases.size() - failures.size();
        System.out.println("tokenizer parity: " + passed + "/" + cases.size());
        if (!failures.isEmpty()) {
            org.junit.jupiter.api.Assertions.fail(failures.size() + " parity failure(s):\n" + String.join("\n", failures));
        }
    }
}
