# frozen_string_literal: true

require_relative "oauth2/authorization_response"
require_relative "oauth2/client"
require_relative "oauth2/error"
require_relative "oauth2/pkce"
require_relative "oauth2/request"
require_relative "oauth2/response_body"
require_relative "oauth2/token"

module SimpleOAuth
  # OAuth 2.0 request builders and response parsers
  #
  # Like the OAuth 1.0 header builder, these build requests and parse responses without
  # performing HTTP themselves, so they work with any HTTP client.
  #
  # @api public
  # @example Exchange an authorization code for a token
  #   client = SimpleOAuth::OAuth2::Client.new(client_id: "id", token_endpoint: "https://example.com/token")
  #   pkce = SimpleOAuth::OAuth2::PKCE.generate
  #   request = client.authorization_code_request(code: "code", redirect_uri: "https://app.example/cb",
  #     code_verifier: pkce.verifier)
  #   response = Net::HTTP.post(URI(request.url), request.body, request.headers)
  #   token = SimpleOAuth::OAuth2::Token.from_response(status: response.code, body: response.body)
  #
  # @see https://www.rfc-editor.org/rfc/rfc6749 RFC 6749 - The OAuth 2.0 Authorization Framework
  # @see https://www.rfc-editor.org/rfc/rfc7636 RFC 7636 - Proof Key for Code Exchange (PKCE)
  # @see https://www.rfc-editor.org/rfc/rfc7009 RFC 7009 - OAuth 2.0 Token Revocation
  module OAuth2
  end
end
