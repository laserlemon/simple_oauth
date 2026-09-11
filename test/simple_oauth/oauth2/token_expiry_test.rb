require "test_helper"

module SimpleOAuth
  module OAuth2
    # Tests for OAuth 2.0 token expiry
    class TokenExpiryTest < Minitest::Test
      cover "SimpleOAuth::OAuth2::Token*"

      ISSUED_AT = Time.utc(2026, 9, 11, 12)

      def setup
        @token = Token.new({"access_token" => "a", "expires_in" => 3600}, issued_at: ISSUED_AT)
      end

      def test_not_expired_before_expiry
        refute @token.expired?(now: ISSUED_AT + 3599)
      end

      def test_expired_at_expiry
        assert @token.expired?(now: ISSUED_AT + 3600)
      end

      def test_leeway_expires_early
        assert @token.expired?(leeway: 30, now: ISSUED_AT + 3570)
        refute @token.expired?(leeway: 30, now: ISSUED_AT + 3569)
      end

      def test_defaults_to_the_current_time
        refute_predicate Token.new({"access_token" => "a", "expires_in" => 60}), :expired?
        assert_predicate Token.new({"access_token" => "a", "expires_in" => 60}, issued_at: Time.now - 61), :expired?
      end

      def test_token_without_lifetime_never_expires
        refute Token.new({"access_token" => "a"}).expired?(now: Time.utc(3000))
      end
    end
  end
end
