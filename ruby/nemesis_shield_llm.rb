# LLM Guard for Ruby — OWASP-LLM-Top-10 detection with the HashLR ML classifier shared across every
# Nemesis Shield SDK. Feature buckets are fnv1a(feature) % dim (the same hash used for HTTP sketches),
# so scores match every other language. Char n-grams over a canonicalized (de-leetspeaked, ASCII-alnum)
# form catch obfuscation the regex layer misses.
require "json"
require "set"
require_relative "nemesis_shield"

module NemesisShield
  module LLM
    MODEL = JSON.parse(File.read(File.join(__dir__, "ml_weights.json"))).freeze
    DIM = MODEL["dim"]
    BIAS = MODEL["bias"]
    WEIGHTS = MODEL["weights"]
    BLOCK = MODEL.fetch("blockThreshold", 0.85)
    FLAG = MODEL.fetch("flagThreshold", 0.45)
    LEET = { "0" => "o", "1" => "i", "3" => "e", "4" => "a", "5" => "s", "7" => "t", "@" => "a", "$" => "s", "8" => "b", "|" => "i" }.freeze
    INJECTION = [
      /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts?|context)/i,
      /disregard\s+(the\s+)?(above|previous|system)/i,
      /(reveal|show|print|repeat)\s+(your|the)\s+(system\s+)?(prompt|instructions)/i,
      /\bDAN\b|do\s+anything\s+now|developer\s+mode|jailbreak/i,
      /(bypass|ignore|disable)\s+(your\s+)?(safety|content\s+policy|guardrails?)/i,
    ].freeze

    module_function

    def canon(text)
      text.downcase.chars.map { |c| LEET[c] || c }.select { |c| c =~ /[a-z0-9]/ }.join
    end

    def bucket(s)
      NemesisShield.fnv1a(s).to_i(16) % DIM
    end

    def features(text)
      b = Set.new
      ws = text.downcase.scan(/[a-z0-9']+/)
      ws.each { |w| b << bucket("w:" + w) }
      (0...(ws.length - 1)).each { |i| b << bucket("b:" + ws[i] + " " + ws[i + 1]) }
      c = canon(text)
      [3, 4, 5].each { |n| (0..(c.length - n)).each { |i| b << bucket("c#{n}:" + c[i, n]) } }
      b << bucket("e:long") if text.length > 2000
      b << bucket("e:nonascii") if text.each_char.count { |ch| ch.ord > 127 } > 3
      b
    end

    def ml_injection_score(text)
      z = BIAS + features(text).sum { |bk| WEIGHTS[bk.to_s] || 0.0 }
      return 0.0 if z < -30
      return 1.0 if z > 30
      1.0 / (1.0 + Math.exp(-z))
    end

    # Returns { blocked:, severity:, kind:, score:, owasp: }. Regex first, then ML for obfuscation.
    def guard_llm(prompt, enforce: false)
      return { blocked: enforce, severity: "high", kind: "prompt_injection", score: 1.0, owasp: "LLM01" } if INJECTION.any? { |re| prompt =~ re }
      s = ml_injection_score(prompt)
      return { blocked: enforce, severity: "high", kind: "ml_prompt_injection", score: s, owasp: "LLM01" } if s >= BLOCK
      return { blocked: false, severity: "medium", kind: "ml_prompt_injection", score: s, owasp: "LLM01" } if s >= FLAG
      { blocked: false, severity: "none", score: s }
    end
  end
end
