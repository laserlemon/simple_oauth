require "test_helper"
require "net/http"

module SimpleOAuth
  # The parameter normalization example of RFC 5849 Section 3.4.1.3
  #
  # This is the specification's own worked example, and the only case here measured against a
  # normalized string the RFC states rather than one this library produced for itself.
  class HeaderRFCNormalizationTest < Minitest::Test
    include TestHelpers

    cover "SimpleOAuth::Header*"

    # RFC 5849 Section 3.4.1.3.1 - the example request
    URL = "http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b".freeze
    BODY = "c2&a3=2+q".freeze
    OPTIONS = {
      consumer_key: "9djdj82h48djs9d2",
      token: "kkk9d7dh3k39sjv7",
      signature_method: "HMAC-SHA1",
      timestamp: "137131201",
      nonce: "7d8f3e4a",
      consumer_secret: "j49sk3j29djd",
      token_secret: "dh893hdasih9"
    }.freeze

    # RFC 5849 Section 3.4.1.3.2 - the normalized parameter string, with oauth_version in the
    # position it sorts into; the RFC example omits it and this library always sends it
    NORMALIZED = "a2=r%20b&a3=2%20q&a3=a&b5=%3D%253D&c%40=&c2=&oauth_consumer_key=9djdj82h48djs9d2&" \
                 "oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1&oauth_timestamp=137131201&" \
                 "oauth_token=kkk9d7dh3k39sjv7&oauth_version=1.0".freeze

    def test_normalized_params_match_the_specification
      assert_equal NORMALIZED, header.send(:normalized_params)
    end

    def test_signature_base_string_matches_the_specification
      # RFC 5849 Section 3.4.1.1 - method, base string URI, and normalized parameters
      expected = "POST&#{Header.escape("http://example.com/request")}&#{Header.escape(NORMALIZED)}"

      assert_equal expected, header.send(:signature_base)
    end

    def test_a_valueless_body_parameter_is_signed_with_an_empty_value
      assert_includes header.send(:normalized_params), "&c2=&"
    end

    def test_a_valueless_body_parameter_parses_to_an_empty_string
      assert_equal [["c2", ""], ["a3", "2"]], Header.send(:form_params, "c2&a3=2")
    end

    def test_a_valueless_query_parameter_is_signed_with_an_empty_value
      valueless = SimpleOAuth::Header.new(:get, "https://example.com/r?flag", {}, OPTIONS)

      assert_includes valueless.send(:url_params), ["flag", ""]
    end

    def test_the_signature_verifies_against_the_same_request
      parsed = SimpleOAuth::Header.from_request(request, header.to_s)

      assert parsed.valid?(consumer_secret: OPTIONS[:consumer_secret], token_secret: OPTIONS[:token_secret])
    end

    private

    def header
      SimpleOAuth::Header.from_request(request, OPTIONS)
    end

    def request
      Net::HTTP::Post.new(URI(URL)).tap do |post|
        post["Content-Type"] = "application/x-www-form-urlencoded"
        post.body = BODY
      end
    end
  end
end
