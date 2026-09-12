# frozen_string_literal: true

require "test_helper"

module SimpleOAuth
  module OAuth2
    # Tests for OAuth 2.0 error responses per RFC 6749 Section 5.2
    class ErrorTest < Minitest::Test
      cover "SimpleOAuth::OAuth2::Error*"

      ERROR_BODY = '{"error":"invalid_grant","error_description":"The code expired",' \
                   '"error_uri":"https://server.example.com/e"}'

      def test_from_response_reads_every_field
        error = Error.from_response(status: 400, body: ERROR_BODY)

        assert_equal "invalid_grant", error.code
        assert_equal "The code expired", error.description
        assert_equal "https://server.example.com/e", error.uri
      end

      def test_from_response_keeps_the_status_and_builds_a_message
        error = Error.from_response(status: 400, body: ERROR_BODY)

        assert_equal 400, error.status
        assert_equal "invalid_grant: The code expired", error.message
      end

      def test_from_response_converts_a_string_status
        assert_equal 401, Error.from_response(status: "401", body: '{"error":"invalid_client"}').status
      end

      def test_message_with_only_a_code
        assert_equal "invalid_request", Error.from_response(status: 400, body: '{"error":"invalid_request"}').message
      end

      def test_message_with_only_a_description
        assert_equal "Try again", Error.new(code: nil, description: "Try again").message
      end

      def test_message_without_details
        assert_equal "OAuth 2.0 request failed with status 500",
          Error.from_response(status: 500, body: "Internal Server Error").message
      end

      def test_non_json_response_has_no_details
        error = Error.from_response(status: 500, body: "Internal Server Error")

        assert_nil error.code
        assert_nil error.description
        assert_nil error.uri
      end

      def test_defaults
        error = Error.new(code: "invalid_scope")

        assert_nil error.description
        assert_nil error.uri
        assert_nil error.status
      end

      def test_is_a_standard_error
        assert_kind_of StandardError, Error.new(code: "invalid_scope")
      end
    end
  end
end
