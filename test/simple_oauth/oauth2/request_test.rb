require "test_helper"

module SimpleOAuth
  module OAuth2
    # Tests for built, unsent OAuth 2.0 requests
    class RequestTest < Minitest::Test
      cover "SimpleOAuth::OAuth2::Request*"

      def setup
        @headers = {"Content-Type" => "application/x-www-form-urlencoded"}
        @request = Request.new(method: "POST", url: "https://server.example.com/token", headers: @headers, body: "a=b")
      end

      def test_method_and_url
        assert_equal "POST", @request.method
        assert_equal "https://server.example.com/token", @request.url
      end

      def test_headers_and_body
        assert_equal @headers, @request.headers
        assert_equal "a=b", @request.body
      end

      def test_headers_are_a_frozen_copy
        assert_predicate @request.headers, :frozen?
        refute_predicate @headers, :frozen?
      end

      def test_frozen
        assert_predicate @request, :frozen?
      end
    end
  end
end
