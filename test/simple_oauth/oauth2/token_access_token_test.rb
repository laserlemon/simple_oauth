require "test_helper"

module SimpleOAuth
  module OAuth2
    # Tests for the access token a token response must carry
    class TokenAccessTokenTest < Minitest::Test
      include OAuth2Examples

      cover "SimpleOAuth::OAuth2::Token*"

      def test_from_response_with_a_null_access_token
        error = assert_raises(Error) { Token.from_response(status: 200, body: '{"access_token":null}') }

        assert_equal "token response has no access_token", error.description
      end

      def test_from_response_with_an_empty_access_token
        assert_raises(Error) { Token.from_response(status: 200, body: '{"access_token":""}') }
      end

      def test_new_with_a_null_access_token
        error = assert_raises(ArgumentError) { Token.new({"access_token" => nil}) }

        assert_equal "The access_token must be a non-empty String", error.message
      end

      def test_new_with_an_empty_access_token
        assert_raises(ArgumentError) { Token.new({"access_token" => ""}) }
      end

      def test_access_token_predicate
        assert Token.access_token?("2YotnFZFEjr1zCsicMWpAA")
        refute Token.access_token?(:symbol)
      end

      def test_access_token_predicate_accepts_string_subclasses
        assert Token.access_token?(Class.new(String).new("2YotnFZFEjr1zCsicMWpAA"))
      end

      def test_new_requires_an_access_token
        assert_raises(KeyError) { Token.new({"token_type" => "bearer"}) }
      end
    end
  end
end
