// LLM Guard for Go — OWASP-LLM-Top-10 (2025) detection with the same HashLR ML classifier every
// Nemesis Shield SDK ships. Feature buckets are fnv1a(feature) % dim (the SAME hash used for HTTP
// sketches), so scores are identical across every language. Complements the regex layer: char
// n-grams over a canonicalized (de-leetspeaked, ASCII-alnum) form catch obfuscation the regex misses.
package nemesis

import (
	_ "embed"
	"encoding/json"
	"math"
	"regexp"
	"strconv"
	"strings"
)

//go:embed ml_weights.json
var mlWeightsJSON []byte

type mlModel struct {
	Version        int                `json:"version"`
	Dim            int                `json:"dim"`
	Bias           float64            `json:"bias"`
	BlockThreshold float64            `json:"blockThreshold"`
	FlagThreshold  float64            `json:"flagThreshold"`
	Weights        map[string]float64 `json:"weights"`
}

var ml mlModel

func init() { _ = json.Unmarshal(mlWeightsJSON, &ml) }

var (
	leet        = strings.NewReplacer("0", "o", "1", "i", "3", "e", "4", "a", "5", "s", "7", "t", "@", "a", "$", "s", "8", "b", "|", "i")
	wordRe      = regexp.MustCompile(`[a-z0-9']+`)
	injectionRe = []*regexp.Regexp{
		regexp.MustCompile(`(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts?|context)`),
		regexp.MustCompile(`(?i)disregard\s+(the\s+)?(above|previous|system)`),
		regexp.MustCompile(`(?i)(reveal|show|print|repeat)\s+(your|the)\s+(system\s+)?(prompt|instructions)`),
		regexp.MustCompile(`(?i)\bDAN\b|do\s+anything\s+now|developer\s+mode|jailbreak`),
		regexp.MustCompile(`(?i)(bypass|ignore|disable)\s+(your\s+)?(safety|content\s+policy|guardrails?)`),
	}
)

func mlCanon(text string) string {
	t := leet.Replace(strings.ToLower(text))
	var b strings.Builder
	for i := 0; i < len(t); i++ {
		c := t[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			b.WriteByte(c)
		}
	}
	return b.String()
}

func mlBucket(s string) int {
	h, _ := strconv.ParseUint(fnv1a(s), 16, 64)
	return int(h % uint64(ml.Dim))
}

func mlFeatures(text string) map[int]struct{} {
	b := make(map[int]struct{})
	ws := wordRe.FindAllString(strings.ToLower(text), -1)
	for _, w := range ws {
		b[mlBucket("w:"+w)] = struct{}{}
	}
	for i := 0; i+1 < len(ws); i++ {
		b[mlBucket("b:"+ws[i]+" "+ws[i+1])] = struct{}{}
	}
	c := mlCanon(text)
	for _, n := range []int{3, 4, 5} {
		for i := 0; i+n <= len(c); i++ {
			b[mlBucket("c"+strconv.Itoa(n)+":"+c[i:i+n])] = struct{}{}
		}
	}
	if len(text) > 2000 {
		b[mlBucket("e:long")] = struct{}{}
	}
	na := 0
	for _, r := range text {
		if r > 127 {
			na++
		}
	}
	if na > 3 {
		b[mlBucket("e:nonascii")] = struct{}{}
	}
	return b
}

// MLInjectionScore returns the probability (0..1) that text is a prompt-injection / jailbreak attempt.
func MLInjectionScore(text string) float64 {
	z := ml.Bias
	for bk := range mlFeatures(text) {
		z += ml.Weights[strconv.Itoa(bk)]
	}
	if z < -30 {
		return 0
	}
	if z > 30 {
		return 1
	}
	return 1 / (1 + math.Exp(-z))
}

// LLMVerdict is the result of guarding one prompt.
type LLMVerdict struct {
	Blocked  bool    `json:"blocked"`
	Severity string  `json:"severity"` // "high" | "medium" | "none"
	Kind     string  `json:"kind"`     // "prompt_injection" | "ml_prompt_injection" | ""
	Score    float64 `json:"score"`
	OWASP    string  `json:"owasp"`
}

// GuardLLM analyzes a prompt with the regex rules + HashLR ML. In enforce mode a high-severity
// detection is blocked. Regex wins first; ML adds coverage for obfuscation the regex misses.
func GuardLLM(prompt string, enforce bool) LLMVerdict {
	for _, re := range injectionRe {
		if re.MatchString(prompt) {
			return LLMVerdict{Blocked: enforce, Severity: "high", Kind: "prompt_injection", Score: 1, OWASP: "LLM01"}
		}
	}
	s := MLInjectionScore(prompt)
	if s >= ml.BlockThreshold {
		return LLMVerdict{Blocked: enforce, Severity: "high", Kind: "ml_prompt_injection", Score: s, OWASP: "LLM01"}
	}
	if s >= ml.FlagThreshold {
		return LLMVerdict{Blocked: false, Severity: "medium", Kind: "ml_prompt_injection", Score: s, OWASP: "LLM01"}
	}
	return LLMVerdict{Blocked: false, Severity: "none", Score: s}
}
