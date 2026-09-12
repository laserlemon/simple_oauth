# frozen_string_literal: true

require "test_helper"

module SimpleOAuth
  # Tests for parsing OAuth credentials from a query string, per RFC 5849 Section 3.5.3
  class HeaderParseQueryTest < Minitest::Test
    cover "SimpleOAuth::Header*"

    def test_parses_oauth_parameters
      parsed = SimpleOAuth::Header.parse_query("oauth_consumer_key=key&oauth_signature=sig&status=hello")

      assert_equal({consumer_key: "key", signature: "sig"}, parsed)
    end

    def test_ignores_parameters_that_are_not_oauth
      assert_empty SimpleOAuth::Header.parse_query("status=hello&count=2")
    end
  end
end
