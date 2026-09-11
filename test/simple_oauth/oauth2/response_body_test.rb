require "test_helper"

module SimpleOAuth
  module OAuth2
    # Tests for parsing OAuth 2.0 response bodies
    class ResponseBodyTest < Minitest::Test
      cover "SimpleOAuth::OAuth2::ResponseBody*"

      def test_parses_a_json_object
        assert_equal({"error" => "invalid_grant"}, ResponseBody.parse('{"error":"invalid_grant"}'))
      end

      def test_non_object_json_is_empty
        assert_empty ResponseBody.parse("[1, 2]")
      end

      def test_invalid_json_is_empty
        assert_empty ResponseBody.parse("Internal Server Error")
      end

      def test_nil_is_empty
        assert_empty ResponseBody.parse(nil)
      end
    end
  end
end
