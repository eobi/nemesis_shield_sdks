Gem::Specification.new do |s|
  s.name        = "nemesis-shield"
  s.version     = "0.1.0"
  s.summary     = "Nemesis Shield — Sentinel SDK for Ruby (positive-security middleware + LLM guard)"
  s.description = "Learn your app's normal behavior, then block off-baseline requests (auth bypass, " \
                  "path traversal, scanners, unusual methods) in enforce mode. Rack/Rails/Sinatra " \
                  "middleware plus an OWASP-LLM prompt-injection guard backed by an embedded ML model " \
                  "(byte-identical across all Nemesis Shield SDKs). Privacy-preserving, fail-open, no runtime deps."
  s.authors     = ["Autogon Inc."]
  s.email       = ["support@nemesislabs.xyz"]
  s.homepage    = "https://nemesislabs.xyz"
  s.license     = "MIT"

  # Flat layout: the SDK is three drop-in files. ml_weights.json must sit beside the .rb files so the
  # LLM guard can load it via __dir__.
  s.files         = ["nemesis_shield.rb", "nemesis_shield_llm.rb", "ml_weights.json", "README.md"]
  s.require_paths = ["."]
  s.required_ruby_version = ">= 2.7"

  s.metadata = {
    "source_code_uri"   => "https://github.com/eobi/nemesis_shield_sdks/tree/main/ruby",
    "homepage_uri"      => "https://nemesislabs.xyz",
    "documentation_uri" => "https://github.com/eobi/nemesis_shield_sdks/blob/main/ruby/README.md",
    "changelog_uri"     => "https://github.com/eobi/nemesis_shield_sdks/releases",
  }
end
