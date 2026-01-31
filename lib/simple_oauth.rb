require_relative "simple_oauth/header"
require_relative "simple_oauth/version"

# OAuth 1.0 header generation and parsing library
#
# SimpleOAuth provides a simple interface for building and verifying
# OAuth 1.0 Authorization headers per RFC 5849.
#
# @example Building an OAuth header
#   header = SimpleOAuth::Header.new(
#     :get,
#     "https://api.example.com/resource",
#     {status: "Hello"},
#     consumer_key: "key",
#     consumer_secret: "secret"
#   )
#   header.to_s # => "OAuth oauth_consumer_key=\"key\", ..."
#
# @example Parsing an OAuth header
#   parsed = SimpleOAuth::Header.parse('OAuth oauth_consumer_key="key"')
#   # => {consumer_key: "key"}
#
# @see https://tools.ietf.org/html/rfc5849 RFC 5849 - The OAuth 1.0 Protocol
module SimpleOAuth
  # Error raised when parsing a malformed OAuth Authorization header
  class ParseError < StandardError; end

  # Error raised when invalid options are passed to Header
  # (defined in header.rb, exported here for convenience)
end
