# Nemesis Shield - Sentinel SDK for Ruby (native: local shape + policy cache + inline blocking).
# Learns your app's normal behavior; in enforce mode blocks off-baseline requests (auth bypass, path
# traversal, scanners, unusual methods) before your app runs. Works with any Rack app - Rails,
# Sinatra, Hanami, raw Rack. Fail-open, privacy-preserving.
#
#   # Rails (config/application.rb):     config.middleware.use NemesisShield::Middleware, token: ENV["NEMESIS_TOKEN"]
#   # Sinatra:                           use NemesisShield::Middleware, token: ENV["NEMESIS_TOKEN"]
require "net/http"
require "json"
require "uri"
require "thread"

module NemesisShield
  DEFAULT_ENDPOINT = "https://shield.nemesislabs.xyz/api/v1/sketches".freeze
  # Canonical value taxonomy - must match the shared engine (tokenize.ts) byte-for-byte so a Ruby
  # app and a Node/Python app produce identical shape hashes.
  UUID = /\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/i
  EMAIL = /\A[^@\s]+@[^@\s]+\.[^@\s]+\z/
  URLRE = /\Ahttps?:\/\/\S+\z/i
  IPV4 = /\A(\d{1,3}\.){3}\d{1,3}\z/
  IPV6 = /\A[0-9a-f:]+:[0-9a-f:]+\z/i
  INT = /\A-?\d+\z/
  FLOATRE = /\A-?\d*\.\d+\z/
  DATE = /\A\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2})?)?/
  JWT = /\A[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\z/
  HEX = /\A[0-9a-f]+\z/i
  B64 = /\A[A-Za-z0-9+\/]+={0,2}\z/
  ALPHA = /\A[A-Za-z]+\z/
  ALNUM = /\A[A-Za-z0-9]+\z/
  # A run of 7+ letters => reads like a word / route name, not an opaque id/token.
  WORD = /[A-Za-z]{7,}/
  # A hostname path segment (network-zone routes like example.com, sub.example.co.uk) collapses to
  # {domain}. Lookahead-free so it ports byte-identically to RE2 engines and matches the edge SDK.
  DOMAIN = /\A([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\z/i
  # A digit, used to tell a generated composite id (inc_ip_1_2_3_4_178..) from a snake_case word.
  DIGIT = /\d/

  module_function

  def normalize_path(path)
    clean = path.to_s.split("?", 2).first.to_s.split("#", 2).first.to_s
    out = clean.split("/").map do |seg|
      next seg if seg.empty?
      next "{traversal}" if seg.include?("..") # path-traversal segment (keeps ".." out of telemetry)
      case kind_of(seg)
      when "int", "float" then "{int}"
      when "uuid" then "{uuid}"
      when "hex" then "{hex}"
      when "base64" then "{token}"
      when "alnum" then (seg.length >= 12 && seg !~ WORD) ? "{id}" : seg
      else
        # Hostnames collapse to {domain}; underscored generated ids that carry a digit (or are very
        # long) collapse to {id}. Kebab route names (iso-27001) have no underscore, so stay literal.
        if seg =~ DOMAIN then "{domain}"
        elsif seg.include?("_") && (seg =~ DIGIT || seg.length >= 20) then "{id}"
        else seg end
      end
    end.join("/")
    out.empty? ? "/" : out
  end

  def kind_of(v)
    return "bool" if v == true || v == false
    return "empty" if v.nil?
    s = v.to_s
    return "empty" if s.empty?
    return "uuid" if s =~ UUID
    return "email" if s =~ EMAIL
    return "url" if s =~ URLRE
    return "ipv4" if s =~ IPV4
    return "ipv6" if s =~ IPV6
    return "jwt" if s =~ JWT
    return "date" if s =~ DATE
    return "int" if s =~ INT
    return "float" if s =~ FLOATRE
    return "hex" if s.length >= 16 && s =~ HEX
    return "base64" if s.length >= 16 && s =~ B64 && s !~ WORD
    return "alpha" if s =~ ALPHA
    return "alnum" if s =~ ALNUM
    "string"
  end

  def fnv1a(str)
    h = 0x811c9dc5
    str.each_byte { |b| h ^= b; h = (h * 0x01000193) & 0xffffffff }
    format("%08x", h)
  end

  # Request signature (method + route + query param kinds + auth). Excludes status by design.
  # Analytics / click-tracking query params carry no application logic and are the main cause of shape
  # explosion (every ad/campaign link adds different ones). Stripped from the signature so a UTM'd
  # request matches the bare route, while real params (and any attack in them) stay modeled. Shared,
  # identical across every Nemesis Shield SDK so the shape hash matches everywhere.
  TRACKING_PREFIXES = %w[utm_ mtm_ pk_ hsa_ matomo_ piwik_ ga_].freeze
  TRACKING_EXACT = %w[gclid gbraid wbraid dclid gclsrc fbclid msclkid twclid ttclid yclid igshid scid wickedid _ga _gl _hsenc _hsmi mc_cid mc_eid vero_id vero_conv oly_anon_id oly_enc_id _openstat rb_clickid s_cid epik sccid].freeze

  def tracking_param?(name)
    n = name.to_s.downcase
    TRACKING_PREFIXES.any? { |p| n.start_with?(p) } || TRACKING_EXACT.include?(n)
  end
  module_function :tracking_param?

  def build_sketch(method:, path:, query: {}, authed: false, status: 0)
    route = normalize_path(path)
    params = (query || {}).keys.reject { |k| tracking_param?(k) }.sort.map { |k| v = query[k]; { name: k.to_s, kind: kind_of(v.is_a?(Array) ? v.first : v), nested: v.is_a?(Array) } }
    # canonical shape input: keys sorted (auth, method, params, route); params are [name, kind, nested];
    # status is intentionally excluded so enforcement can decide BEFORE the response exists.
    canon = JSON.generate({ auth: authed ? 1 : 0, method: method.to_s.upcase, params: params.map { |p| [p[:name], p[:kind], p[:nested] ? 1 : 0] }, route: route })
    { route: route, method: method.to_s.upcase, authenticated: authed, status: status, params: params, shape: fnv1a(canon) }
  end

  # Safe-unlock (break-glass): paths never blocked, so a still-learning baseline can't lock operators
  # out of the doors they need to fix it. Prefix-matched. Override with the NEMESIS_SHIELD_BOOTSTRAP
  # env (comma-separated) or the `bootstrap:` option.
  DEFAULT_BOOTSTRAP = ["/login", "/signin", "/sign-in", "/auth", "/oauth", "/session", "/wp-login.php", "/wp-admin"].freeze

  def resolve_bootstrap(cfg)
    return cfg.map(&:to_s) if cfg.is_a?(Array)
    env = ENV["NEMESIS_SHIELD_BOOTSTRAP"].to_s
    return env.split(",").map(&:strip).reject(&:empty?) unless env.strip.empty?
    DEFAULT_BOOTSTRAP.dup
  end
  module_function :resolve_bootstrap

  class Client
    def initialize(token, endpoint: DEFAULT_ENDPOINT, flush_interval: 2, bootstrap: nil)
      @token = token
      @uri = URI(endpoint)
      @mode = "observe"
      @shapes = {}
      @known_bad = []
      @baseline = false
      @buffer = []
      @bootstrap = NemesisShield.resolve_bootstrap(bootstrap)
      @mu = Mutex.new
      if token && flush_interval && flush_interval > 0
        refresh
        Thread.new do
          loop { sleep flush_interval; flush; refresh }
        end
      end
    end

    def enforcing?
      @mu.synchronize { @mode == "enforce" }
    end

    # Break-glass: is this path on the never-block bootstrap allow-list? Prefix match.
    def never_block(path)
      p = path.to_s.split("?").first.to_s.split("#").first.to_s.downcase
      @bootstrap.any? { |b| !b.empty? && p.start_with?(b.downcase) }
    end

    def decide(sketch)
      @mu.synchronize do
        per = @shapes[sketch[:shape]]
        return [false, nil] if per == "allow"
        return [true, "policy: blocked shape"] if per == "block"
        return [true, "global threat intelligence"] if @known_bad.include?(sketch[:shape])
        return [true, "off-baseline: unapproved behavior"] if @baseline
        [false, nil]
      end
    end

    def record(sketch)
      flush_now = false
      @mu.synchronize { @buffer << sketch; flush_now = @buffer.size >= 50 }
      flush if flush_now
    end

    def flush
      batch = @mu.synchronize { b = @buffer; @buffer = []; b }
      send_batch(batch) unless batch.empty?
    end

    def refresh
      send_batch([])
    end

    def send_batch(batch)
      http = Net::HTTP.new(@uri.host, @uri.port)
      http.use_ssl = @uri.scheme == "https"
      http.open_timeout = 2
      http.read_timeout = 3
      req = Net::HTTP::Post.new(@uri, "Authorization" => "Bearer #{@token}", "Content-Type" => "application/json")
      req.body = JSON.generate({ sketches: batch })
      res = http.request(req)
      return unless res.is_a?(Net::HTTPSuccess)
      data = JSON.parse(res.body)
      @mu.synchronize do
        @mode = data["mode"] if data["mode"]
        pol = data["policy"] || {}
        if pol["shapes"]
          @shapes = pol["shapes"]
          @baseline = true unless @shapes.empty?
        end
        @known_bad = pol["knownBad"] if pol["knownBad"]
      end
    rescue StandardError
      nil # fail-open
    end
  end

  # Rack middleware (Rails / Sinatra / any Rack app).
  class Middleware
    def initialize(app, token:, endpoint: DEFAULT_ENDPOINT, **kw)
      @app = app
      @client = Client.new(token, endpoint: endpoint, **kw)
    end

    def call(env)
      method = env["REQUEST_METHOD"]
      path = env["PATH_INFO"].to_s
      authed = !env["HTTP_AUTHORIZATION"].nil? || !env["HTTP_COOKIE"].nil? || !env["HTTP_X_API_KEY"].nil?
      query = begin
        require "rack/utils"
        Rack::Utils.parse_query(env["QUERY_STRING"].to_s)
      rescue StandardError
        # stdlib fallback so query-param STRUCTURE is still fed when rack isn't loaded
        begin
          URI.decode_www_form(env["QUERY_STRING"].to_s).to_h
        rescue StandardError
          {}
        end
      end
      if @client.enforcing? && !@client.never_block(path)
        block, reason = @client.decide(NemesisShield.build_sketch(method: method, path: path, query: query, authed: authed))
        if block
          @client.record(NemesisShield.build_sketch(method: method, path: path, query: query, authed: authed, status: 403))
          body = JSON.generate({ error: "blocked_by_nemesis_shield", reason: reason })
          return [403, { "content-type" => "application/json" }, [body]]
        end
      end
      status, headers, response = @app.call(env)
      @client.record(NemesisShield.build_sketch(method: method, path: path, query: query, authed: authed, status: status))
      [status, headers, response]
    end
  end
end
