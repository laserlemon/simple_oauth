# frozen_string_literal: true

require "test_helper"

module SimpleOAuth
  module OAuth2
    # Tests for OAuth 2.0 token responses per RFC 6749 Section 5.1
    class TokenTest < Minitest::Test
      include OAuth2Examples

      cover "SimpleOAuth::OAuth2::Token*"

      ISSUED_AT = Time.utc(2026, 9, 11, 12)

      def setup
        @token = Token.from_response(status: 200, body: TOKEN_RESPONSE, issued_at: ISSUED_AT)
      end

      def test_from_response_reads_rfc_6749_example
        assert_equal ACCESS_TOKEN, @token.access_token
        assert_equal "example", @token.token_type
        assert_equal REFRESH_TOKEN, @token.refresh_token
      end

      def test_from_response_computes_the_expiration
        assert_equal 3600, @token.expires_in
        assert_equal ISSUED_AT + 3600, @token.expires_at
      end

      def test_params_keep_unspecified_parameters
        assert_equal "example_value", @token.params["example_parameter"]
        assert_predicate @token.params, :frozen?
      end

      def test_from_response_accepts_any_successful_status
        assert_equal ACCESS_TOKEN, Token.from_response(status: "201", body: TOKEN_RESPONSE).access_token
        assert_equal ACCESS_TOKEN, Token.from_response(status: 299, body: TOKEN_RESPONSE).access_token
      end

      def test_from_response_raises_the_endpoint_error
        error = assert_raises(Error) { Token.from_response(status: 400, body: '{"error":"invalid_grant"}') }

        assert_equal "invalid_grant", error.code
        assert_equal 400, error.status
      end

      def test_from_response_rejects_statuses_outside_2xx
        assert_raises(Error) { Token.from_response(status: 199, body: TOKEN_RESPONSE) }
        assert_raises(Error) { Token.from_response(status: "300", body: TOKEN_RESPONSE) }
      end

      def test_from_response_without_access_token
        error = assert_raises(Error) { Token.from_response(status: "200", body: '{"token_type":"bearer"}') }

        assert_equal "token response has no access_token", error.description
        assert_equal 200, error.status
      end

      def test_from_response_without_access_token_has_no_error_code
        assert_nil assert_raises(Error) { Token.from_response(status: 200, body: "{}") }.code
      end

      def test_from_response_defaults_issued_at_to_now
        before = Time.now
        token = Token.from_response(status: 200, body: '{"access_token":"a","expires_in":60}')

        assert_operator token.expires_at, :>=, before + 60
        assert_operator token.expires_at, :<=, Time.now + 60
      end

      def test_new_accepts_symbol_keys
        token = Token.new({access_token: "a", scope: "tweet.read users.read"})

        assert_equal({"access_token" => "a", "scope" => "tweet.read users.read"}, token.params)
        assert_equal "tweet.read users.read", token.scope
      end

      def test_new_accepts_a_string_lifetime
        token = Token.new({"access_token" => "a", "expires_in" => "60"}, issued_at: ISSUED_AT)

        assert_equal 60, token.expires_in
        assert_equal ISSUED_AT + 60, token.expires_at
      end

      def test_new_defaults_issued_at_to_now
        before = Time.now
        token = Token.new({"access_token" => "a", "expires_in" => 60})

        assert_operator token.expires_at, :>=, before + 60
        assert_operator token.expires_at, :<=, Time.now + 60
      end

      def test_token_without_lifetime
        token = Token.new({"access_token" => "a"})

        assert_nil token.expires_in
        assert_nil token.expires_at
      end

      def test_token_without_type_or_refresh_token
        token = Token.new({"access_token" => "a"})

        assert_nil token.token_type
        assert_nil token.refresh_token
      end

      def test_scopes
        assert_equal %w[tweet.read users.read],
          Token.new({"access_token" => "a", "scope" => "tweet.read users.read"}).scopes
        assert_empty Token.new({"access_token" => "a"}).scopes
      end

      def test_frozen
        assert_predicate @token, :frozen?
      end
    end
  end
end
