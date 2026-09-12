require "test_helper"

module SimpleOAuth
  # Tests for the error hierarchy the library raises
  class ErrorsTest < Minitest::Test
    cover "SimpleOAuth*"

    def test_parse_error_is_a_library_error
      assert_raises(Error) { Header.parse("not a header") }
    end

    def test_invalid_options_error_is_a_library_error
      assert_raises(Error) { Header.new(:get, "https://example.com", {}, unknown: "key").to_s }
    end

    def test_oauth2_error_is_a_library_error
      assert_raises(Error) { OAuth2::Token.from_response(status: 400, body: '{"error":"invalid_grant"}') }
    end

    def test_library_error_is_a_standard_error
      assert_operator Error, :<, StandardError
    end
  end
end
