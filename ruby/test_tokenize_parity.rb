# Canonical tokenizer parity test - asserts normalize_path(path) == expect for every vector in the
# shared source of truth (../tokenize.vectors.json, key "normalizePath"). Proves the Ruby SDK produces
# byte-identical route templates to every other Nemesis Shield SDK. Run: ruby test_tokenize_parity.rb
require_relative "nemesis_shield"
require "json"

vectors = JSON.parse(File.read(File.join(__dir__, "..", "tokenize.vectors.json")))["normalizePath"]

pass = 0
fails = []
vectors.each do |v|
  got = NemesisShield.normalize_path(v["path"])
  if got == v["expect"]
    pass += 1
  else
    fails << v.merge("got" => got)
  end
end

fails.each do |f|
  puts "\e[31m✗\e[0m #{f['path'].inspect}"
  puts "    expected: #{f['expect'].inspect}"
  puts "    got:      #{f['got'].inspect}   (#{f['why']})"
end

puts "\n#{pass}/#{vectors.size} vectors pass"
if fails.empty?
  puts "\e[32mALL #{vectors.size} CANONICAL VECTORS PASS\e[0m"
  exit 0
else
  puts "\e[31m#{fails.size} FAILED\e[0m"
  exit 1
end
