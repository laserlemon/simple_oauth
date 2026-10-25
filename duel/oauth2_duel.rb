# frozen_string_literal: true

require_relative "duel_helper"

# Building OAuth 2.0 requests and reading their responses, which a client
# does once per sign-in or token refresh

setup { @client = SimpleOAuth::OAuth2::Client.new(**DuelHelper::OAUTH2_CLIENT) }

duel "oauth2: PKCE challenge from a verifier" do
  SimpleOAuth::OAuth2::PKCE.new(verifier: DuelHelper::PKCE_VERIFIER)
end

duel "oauth2: authorization URL with PKCE" do
  once { @pkce = SimpleOAuth::OAuth2::PKCE.new(verifier: DuelHelper::PKCE_VERIFIER) }
  @client.authorization_url(redirect_uri: "https://client.example.com/cb", pkce: @pkce, state: "xyz",
    scope: %w[openid profile email])
end

duel "oauth2: authorization code token request" do
  @client.authorization_code_request(code: "SplxlOBeZQQYbYS6WxSbIA", redirect_uri: "https://client.example.com/cb",
    code_verifier: DuelHelper::PKCE_VERIFIER)
end

duel "oauth2: refresh token request" do
  @client.refresh_token_request(refresh_token: "tGzv3JOkF0XG5Qx2TlKWIA", scope: "read write")
end

duel "oauth2: parse an authorization response" do
  SimpleOAuth::OAuth2::AuthorizationResponse.parse("code=SplxlOBeZQQYbYS6WxSbIA&state=xyz&iss=https%3A%2F%2Fserver.example.com",
    state: "xyz", issuer: "https://server.example.com")
end

duel "oauth2: parse a token response" do
  once do
    @issued_at = Time.at(1_700_000_000)
    @body = JSON.generate(access_token: "2YotnFZFEjr1zCsicMWpAA", token_type: "Bearer", expires_in: 3600,
      refresh_token: "tGzv3JOkF0XG5Qx2TlKWIA", scope: "read write")
  end
  SimpleOAuth::OAuth2::Token.from_response(status: 200, body: @body, issued_at: @issued_at)
end

duel "oauth2: parse an error response" do
  once { @body = %({"error":"invalid_grant","error_description":"The code has expired"}) }
  SimpleOAuth::OAuth2::Error.from_response(status: 400, body: @body)
end
