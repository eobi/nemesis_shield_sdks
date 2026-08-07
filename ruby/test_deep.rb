# Deep coverage test - drives the real Rack middleware end to end and proves the Ruby SDK SEES an
# attacker's request from ANY route and blocks it in enforce mode, plus the safe-unlock and fail-open.
# Run: ruby test_deep.rb
require_relative "nemesis_shield"
require "uri"

$pass = 0
$fail = 0
def ok(cond, msg)
  if cond then $pass += 1; puts "  \e[32m✓\e[0m #{msg}"
  else $fail += 1; puts "  \e[31m✗ #{msg}\e[0m" end
end

APP = ->(_env) { [200, { "content-type" => "text/plain" }, ["ok"]] }

def mw(mode: "enforce", allow: [], known_bad: [], bootstrap: nil)
  m = NemesisShield::Middleware.new(APP, token: "t", bootstrap: bootstrap, flush_interval: 0)
  c = m.instance_variable_get(:@client)
  c.instance_variable_set(:@mode, mode)
  c.instance_variable_set(:@shapes, allow.map { |s| [s, "allow"] }.to_h)
  c.instance_variable_set(:@known_bad, known_bad)
  c.instance_variable_set(:@baseline, !allow.empty? || !known_bad.empty?)
  m
end

def env_for(method: "GET", path: "/", qs: "", authed: false)
  e = { "REQUEST_METHOD" => method, "PATH_INFO" => path, "QUERY_STRING" => qs }
  e["HTTP_AUTHORIZATION"] = "Bearer x" if authed
  e
end

def blocked?(m, **kw)
  status, = m.call(env_for(**kw))
  status == 403
end

def shape_of(method, path, qs, authed)
  q = (URI.decode_www_form(qs).to_h rescue {})
  NemesisShield.build_sketch(method: method, path: path, query: q, authed: authed)[:shape]
end

ALLOW = [
  shape_of("GET", "/", "", false),
  shape_of("GET", "/products/12345", "", false),
  shape_of("GET", "/search", "q=shoes", false),
  shape_of("POST", "/api/orders", "", true),
]

puts "\e[1mNemesis Shield - Ruby deep coverage test\e[0m"

puts "\n\e[1m1 · query params change the shape\e[0m"
ok(shape_of("GET", "/search", "q=x", false) != shape_of("GET", "/search", "q=x&inject=1", false), "adding a param changes the shape")
ok(shape_of("GET", "/search", "q=shoes", false) != shape_of("GET", "/search", "q=' OR 1=1", false), "param kind change changes the shape")

puts "\n\e[1m2 · enforce - attacks from ANY route blocked, approved passes\e[0m"
m = mw(allow: ALLOW)
ok(!blocked?(m, path: "/"), "approved GET / passes")
ok(!blocked?(m, path: "/products/999"), "approved GET /products/{int} passes")
ok(!blocked?(m, path: "/search", qs: "q=boots"), "approved GET /search?q=<alnum> passes")
ok(!blocked?(m, method: "POST", path: "/api/orders", authed: true), "approved authed POST passes")
ok(blocked?(m, path: "/.env"), "scanner /.env blocked")
ok(blocked?(m, path: "/wp-config.php.bak"), "scanner /wp-config.php.bak blocked")
ok(blocked?(m, path: "/search", qs: "q=x&cmd=id"), "injected param ?cmd=id blocked")
ok(blocked?(m, path: "/search", qs: "q=' OR 1=1--"), "SQLi-shaped param blocked")
ok(blocked?(m, method: "POST", path: "/"), "method anomaly POST / blocked")
ok(blocked?(m, path: "/api/orders"), "auth anomaly (unauth) blocked")
ok(blocked?(m, path: "/admin/config"), "unknown /admin/config blocked")

puts "\n\e[1m3 · knownBad (global threat intel)\e[0m"
bad = shape_of("POST", "/xmlrpc.php", "", false)
ok(blocked?(mw(allow: ALLOW, known_bad: [bad]), method: "POST", path: "/xmlrpc.php"), "knownBad shape blocked")

puts "\n\e[1m4 · safe-unlock - auth path never blocked\e[0m"
ok(!blocked?(m, method: "POST", path: "/login", qs: "next=x"), "/login never blocked")
ok(!blocked?(m, path: "/wp-login.php"), "/wp-login.php never blocked")
tight = mw(allow: ALLOW, bootstrap: ["/custom-auth"])
ok(blocked?(tight, method: "POST", path: "/login"), "custom bootstrap replaces default")
ok(!blocked?(tight, method: "POST", path: "/custom-auth"), "custom bootstrap honored")

puts "\n\e[1m5 · fail-open + observe\e[0m"
ok(!blocked?(mw(allow: []), path: "/.env"), "fail-open with no baseline")
ok(!blocked?(mw(mode: "observe", allow: ALLOW), path: "/.env"), "observe mode never blocks")

puts "\n" + "─" * 52
if $fail.zero? then puts "\e[32m\e[1mALL #{$pass} CHECKS PASSED\e[0m"; exit 0
else puts "\e[31m\e[1m#{$fail} FAILED\e[0m, #{$pass} passed"; exit 1 end
