# LLM Guard for Ruby - OWASP-LLM-Top-10 detection with the HashLR ML classifier shared across every
# Nemesis Shield SDK. Feature buckets are fnv1a(feature) % dim (the same hash used for HTTP sketches),
# so scores match every other language. Char n-grams over a canonicalized (de-leetspeaked, ASCII-alnum)
# form catch obfuscation the regex layer misses.
require "json"
require "set"
require_relative "nemesis_shield"

module NemesisShield
  module LLM
    MODEL = JSON.parse(File.read(File.join(__dir__, "ml_weights.json"))).freeze
    DIM = MODEL["dim"] # feature space is fixed across versions - only weights/bias/thresholds swap
    # Swappable model state (module ivars so refresh_model can hot-swap a newer published version).
    @bias = MODEL["bias"]
    @weights = MODEL["weights"]
    @block = MODEL.fetch("blockThreshold", 0.85)
    @flag = MODEL.fetch("flagThreshold", 0.45)
    @version = MODEL.fetch("version", 1)
    # Ed25519 public key (hex) that signs published models. Cloud pulls MUST carry a valid signature
    # over the exact bytes; unsigned or tampered bundles are rejected and the embedded model is kept.
    MODEL_PUBLIC_KEY_HEX = "79d81a3b41966b379a9ba719155b8713f70bb341c3e8fab09fd5563a59893d28"
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
      z = @bias + features(text).sum { |bk| @weights[bk.to_s] || 0.0 }
      return 0.0 if z < -30
      return 1.0 if z > 30
      1.0 / (1.0 + Math.exp(-z))
    end

    # Returns { blocked:, severity:, kind:, score:, owasp: }. Regex first, then ML for obfuscation.
    def guard_llm(prompt, enforce: false)
      return { blocked: enforce, severity: "high", kind: "prompt_injection", score: 1.0, owasp: "LLM01" } if INJECTION.any? { |re| prompt =~ re }
      s = ml_injection_score(prompt)
      return { blocked: enforce, severity: "high", kind: "ml_prompt_injection", score: s, owasp: "LLM01" } if s >= @block
      return { blocked: false, severity: "medium", kind: "ml_prompt_injection", score: s, owasp: "LLM01" } if s >= @flag
      { blocked: false, severity: "none", score: s }
    end

    def model_version
      @version
    end

    def verify_model_signature(raw, sig_b64)
      require "openssl"
      require "base64"
      return true if MODEL_PUBLIC_KEY_HEX.empty? # no key pinned - version gate + HTTPS apply
      return false if sig_b64.nil? || sig_b64.empty? # key pinned but bundle unsigned - reject
      pk = OpenSSL::PKey.new_raw_public_key("ED25519", [MODEL_PUBLIC_KEY_HEX].pack("H*"))
      pk.verify(nil, Base64.strict_decode64(sig_b64), raw)
    rescue StandardError
      false
    end

    # Hot-swap the HashLR model from a cloud URL if a newer signed version is published, so the model
    # can be retrained and pushed centrally without redeploying the SDK. Returns the new version number
    # if updated, else nil. Fail-safe: on any error the current (embedded) model is kept.
    # URL defaults to env NEMESIS_MODEL_URL.
    def refresh_model(url = ENV["NEMESIS_MODEL_URL"], timeout: 5.0)
      return nil if url.nil? || url.empty?
      require "net/http"
      require "uri"
      uri = URI(url)
      res = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == "https",
                            open_timeout: timeout, read_timeout: timeout) { |h| h.get(uri.request_uri) }
      return nil unless res.is_a?(Net::HTTPSuccess)
      raw = res.body
      return nil unless verify_model_signature(raw, res["x-model-signature"]) # integrity gate
      m = JSON.parse(raw)
      return nil if m["version"].to_i <= @version.to_i || (m["dim"] && m["dim"].to_i != DIM) # version/dim gate
      @weights = m["weights"]
      @bias = m["bias"]
      @version = m["version"].to_i
      @block = m.fetch("blockThreshold", @block)
      @flag = m.fetch("flagThreshold", @flag)
      @version
    rescue StandardError
      nil
    end
  end
end
