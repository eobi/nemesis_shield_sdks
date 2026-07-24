# Nemesis Shield — Sentinel client for Ruby.
#
# As Rack middleware (Rails/Sinatra):
#
#   use NemesisShield::Middleware, token: ENV["NEMESIS_TOKEN"]
#
# Or report manually after a response. Ships only privacy-preserving metadata (method, path shape,
# status, authenticated?). Never ships request bodies. Fail-open.
require "net/http"
require "json"
require "uri"

module NemesisShield
  OBSERVE_URL = "https://shield.nemesislabs.xyz/api/v1/observe".freeze

  module_function

  # Collapse IDs so the baseline doesn't explode: /orders/123 -> /orders/{int}
  def path_shape(path)
    path.split("?", 2).first.to_s.split("/").map do |seg|
      if seg =~ /\A\d+\z/ then "{int}"
      elsif seg =~ /\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/i then "{uuid}"
      elsif seg =~ /\A[0-9a-f]{16,}\z/i then "{hex}"
      else seg end
    end.join("/")
  end

  # Fire-and-forget report of one or more events. Never raises.
  def report(token, events, endpoint: OBSERVE_URL)
    return if token.nil? || events.nil? || events.empty?
    uri = URI(endpoint)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = uri.scheme == "https"
    http.open_timeout = 2
    http.read_timeout = 2
    req = Net::HTTP::Post.new(uri, "Authorization" => "Bearer #{token}", "Content-Type" => "application/json")
    req.body = { events: events }.to_json
    Thread.new { http.request(req) rescue nil } # off the request path; ignore errors
  rescue StandardError
    nil
  end

  # Rack middleware.
  class Middleware
    def initialize(app, token:, endpoint: OBSERVE_URL)
      @app = app
      @token = token
      @endpoint = endpoint
    end

    def call(env)
      status, headers, body = @app.call(env)
      authed = !env["HTTP_AUTHORIZATION"].nil? || !env["HTTP_COOKIE"].nil?
      NemesisShield.report(@token, [{
        method: env["REQUEST_METHOD"],
        path: NemesisShield.path_shape(env["PATH_INFO"].to_s),
        status: status,
        authenticated: authed
      }], endpoint: @endpoint)
      [status, headers, body]
    end
  end
end
