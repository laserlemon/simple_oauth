require "test_helper"

module SimpleOAuth
  module OAuth2
    # Tests for the HTTP status a response carries
    class ErrorStatusTest < Minitest::Test
      include OAuth2Examples

      cover "SimpleOAuth::OAuth2::Error*"

      def test_http_status_accepts_an_integer_or_a_string
        assert_equal 400, Error.http_status(400)
        assert_equal 400, Error.http_status("400")
      end

      def test_http_status_rejects_a_nil_status
        error = assert_raises(ArgumentError) { Error.http_status(nil) }

        assert_equal "The status must be an Integer or a String of digits: nil", error.message
      end

      def test_http_status_rejects_a_status_that_is_not_a_number
        assert_raises(ArgumentError) { Error.http_status("oops") }
      end

      def test_from_response_rejects_a_nil_status
        assert_raises(ArgumentError) { Error.from_response(status: nil, body: nil) }
      end

      def test_token_from_response_rejects_a_status_that_is_not_a_number
        assert_raises(ArgumentError) { Token.from_response(status: "oops", body: TOKEN_RESPONSE) }
      end
    end
  end
end
