# E2E live round-trip for the Ruby SDK. Builds a real sketch per fixed route via the SDK's own
# build_sketch, prints the shape hash, then POSTs the batch to the LIVE sketches endpoint.
require_relative "nemesis_shield"
require "json"
require "net/http"
require "uri"

token = ENV["NEMESIS_TOKEN"] || ""
endpoint = "https://shield.nemesislabs.xyz/api/v1/sketches"
routes = [
  ["GET", "/app/incidents/inc_ip_1_2_3_4_1786400000000"],
  ["GET", "/app/network/autogon.ai"],
  ["GET", "/app/applications/f47ac10b-58cc-4372-a567-0e02b2c3d479"],
]

sketches = routes.map do |method, path|
  s = NemesisShield.build_sketch(method: method, path: path, authed: false, status: 200)
  puts "SHAPE #{path} route=#{s[:route]} hash=#{s[:shape]}"
  s
end

uri = URI(endpoint)
http = Net::HTTP.new(uri.host, uri.port)
http.use_ssl = true
req = Net::HTTP::Post.new(uri)
req["Authorization"] = "Bearer #{token}"
req["Content-Type"] = "application/json"
req.body = JSON.generate({ sketches: sketches })
begin
  res = http.request(req)
  puts "POST_STATUS #{res.code}"
rescue => e
  puts "POST_STATUS ERR #{e}"
end
