# frozen_string_literal: true

require "test_helper"

module SimpleOAuth
  module OAuth2
    # Tests for the caller's own parameters on a token or revocation request
    class ClientExtraParamsTest < Minitest::Test
      include OAuth2Examples

      cover "SimpleOAuth::OAuth2::Client*"

      def test_authorization_code_request_carries_a_resource_indicator
        # RFC 8707 Section 2 - the audience the client wants the token for
        request = confidential_client.authorization_code_request(code: CODE, redirect_uri: REDIRECT_URI,
          params: {resource: "https://api.example/"})

        assert_includes request.body, "resource=https%3A%2F%2Fapi.example%2F"
      end

      def test_refresh_token_request_carries_extra_params
        request = confidential_client.refresh_token_request(refresh_token: REFRESH_TOKEN,
          params: {audience: "https://api.example/"})

        assert_includes request.body, "audience=https%3A%2F%2Fapi.example%2F"
      end

      def test_client_credentials_request_carries_extra_params
        request = confidential_client.client_credentials_request(params: {resource: "https://api.example/"})

        assert_includes request.body, "resource=https%3A%2F%2Fapi.example%2F"
      end

      def test_revocation_request_carries_extra_params
        request = confidential_client.revocation_request(token: ACCESS_TOKEN, params: {tenant: "acme"})

        assert_includes request.body, "tenant=acme"
      end

      def test_extra_params_with_a_string_key_override_rather_than_repeat
        request = confidential_client.refresh_token_request(refresh_token: REFRESH_TOKEN,
          params: {"grant_type" => "urn:ietf:params:oauth:grant-type:token-exchange"})

        assert_equal 1, request.body.scan("grant_type=").length
        assert_includes request.body, "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange"
      end

      def test_extra_params_can_replace_the_client_id_a_public_client_sends
        request = public_client.authorization_code_request(code: CODE, redirect_uri: REDIRECT_URI,
          params: {client_id: "other"})

        assert_includes request.body, "client_id=other"
        refute_includes request.body, "client_id=#{CLIENT_ID}"
      end

      def test_a_nil_extra_param_is_omitted
        request = confidential_client.revocation_request(token: ACCESS_TOKEN, params: {tenant: nil})

        refute_includes request.body, "tenant"
      end

      def test_no_extra_params_leaves_the_body_unchanged
        assert_equal confidential_client.revocation_request(token: ACCESS_TOKEN).body,
          confidential_client.revocation_request(token: ACCESS_TOKEN, params: {}).body
      end
    end
  end
end
