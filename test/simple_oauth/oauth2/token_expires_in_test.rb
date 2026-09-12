# frozen_string_literal: true

require "test_helper"

module SimpleOAuth
  module OAuth2
    # Tests for the lifetime a token response may carry
    class TokenExpiresInTest < Minitest::Test
      include OAuth2Examples

      cover "SimpleOAuth::OAuth2::Token*"

      def test_from_response_with_a_lifetime_that_is_not_a_number
        error = assert_raises(Error) { token_response('"soon"') }

        assert_equal "token response has an invalid expires_in", error.description
        assert_equal 200, error.status
      end

      def test_from_response_with_a_boolean_lifetime
        assert_raises(Error) { token_response("true") }
      end

      def test_from_response_with_an_object_lifetime
        assert_raises(Error) { token_response('{"seconds":60}') }
      end

      def test_from_response_with_a_lifetime_in_a_string
        assert_equal 3600, token_response('"3600"').expires_in
      end

      def test_from_response_with_a_fractional_lifetime
        assert_equal 3600, token_response("3600.9").expires_in
      end

      def test_from_response_without_a_lifetime
        token = Token.from_response(status: 200, body: %({"access_token":"#{ACCESS_TOKEN}"}))

        assert_nil token.expires_in
        assert_nil token.expires_at
      end

      def test_new_with_a_lifetime_that_is_not_a_number
        error = assert_raises(ArgumentError) { Token.new({"access_token" => ACCESS_TOKEN, "expires_in" => "soon"}) }

        assert_equal "The expires_in must be a number of seconds", error.message
      end

      def test_expires_in_predicate_accepts_seconds
        assert Token.expires_in?(3600)
        assert Token.expires_in?("3600")
      end

      def test_expires_in_predicate_accepts_no_lifetime
        assert Token.expires_in?(nil)
      end

      def test_expires_in_predicate_rejects_values_that_are_not_seconds
        refute Token.expires_in?("soon")
        refute Token.expires_in?(true)
      end

      def test_rejection_reason
        assert_nil Token.rejection_reason({"access_token" => ACCESS_TOKEN, "expires_in" => 3600})
        assert_equal "token response has no access_token", Token.rejection_reason({})
        assert_equal "token response has an invalid expires_in",
          Token.rejection_reason({"access_token" => ACCESS_TOKEN, "expires_in" => "soon"})
      end

      private

      def token_response(expires_in)
        Token.from_response(status: 200, body: %({"access_token":"#{ACCESS_TOKEN}","expires_in":#{expires_in}}))
      end
    end
  end
end
