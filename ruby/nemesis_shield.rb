# Nemesis Shield — Sentinel SDK for Ruby (native: local shape + policy cache + inline blocking).
# Learns your app's normal behavior; in enforce mode blocks off-baseline requests (auth bypass, path
# traversal, scanners, unusual methods) before your app runs. Works with any Rack app — Rails,
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
  UUID = /\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/i
  HEX = /\A[0-9a-f]{16,}\z/i
  INT = /\A\d+\z/

  module_function

  def normalize_path(path)
    path.to_s.split("?", 2).first.to_s.split("/").map do |seg|
      if seg =~ INT then "{int}"
      elsif seg =~ UUID then "{uuid}"
      elsif seg =~ HEX then "{hex}"
      else seg end
    end.join("/")
  end

  def kind_of(v)
    s = v.to_s
    if s =~ INT then "int"
    elsif s =~ UUID then "uuid"
    elsif s =~ HEX then "hex"
    elsif s.include?("@") then "email"
    else "string" end
  end

  def fnv1a(str)
    h = 0x811c9dc5
    str.each_byte { |b| h ^= b; h = (h * 0x01000193) & 0xffffffff }
    format("%08x", h)
  end

  # Request signature (method + route + query param kinds + auth). Excludes status by design.
  def build_sketch(method:, path:, query: {}, authed: false, status: 0)
    route = normalize_path(path)
    params = (query || {}).keys.sort.map { |k| { name: k.to_s, kind: kind_of((query[k].is_a?(Array) ? query[k].first : query[k])) } }
    canon = JSON.generate({ route: route, method: method.to_s.upcase, params: params.map { |p| [p[:name], p[:kind]] }, auth: authed ? 1 : 0 })
    { route: route, method: method.to_s.upcase, authenticated: authed, status: status, params: params, shape: fnv1a(canon) }
  end

  class Client
    def initialize(token, endpoint: DEFAULT_ENDPOINT, flush_interval: 2)
      @token = token
      @uri = URI(endpoint)
      @mode = "observe"
      @shapes = {}
      @known_bad = []
      @baseline = false
      @buffer = []
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
        {}
      end
      if @client.enforcing?
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
