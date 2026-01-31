require "test_helper"

module SimpleOAuth
  class HeaderParseFormBodyTest < Minitest::Test
    cover "SimpleOAuth::Header*"

    # .parse_form_body tests

    def test_parse_form_body_returns_a_hash
      body = "oauth_consumer_key=key123&oauth_token=token456"
      parsed = SimpleOAuth::Header.parse_form_body(body)

      assert_kind_of Hash, parsed
    end

    def test_parse_form_body_extracts_oauth_parameters
      body = "oauth_consumer_key=key123&oauth_token=token456&oauth_signature=sig789"
      parsed = SimpleOAuth::Header.parse_form_body(body)

      assert_equal "key123", parsed[:consumer_key]
      assert_equal "token456", parsed[:token]
      assert_equal "sig789", parsed[:signature]
    end

    def test_parse_form_body_ignores_non_oauth_parameters
      body = "oauth_consumer_key=key123&status=hello%20world&oauth_token=token456"
      parsed = SimpleOAuth::Header.parse_form_body(body)

      assert_equal 2, parsed.keys.size
      assert_equal "key123", parsed[:consumer_key]
      assert_equal "token456", parsed[:token]
      refute parsed.key?(:status)
    end

    def test_parse_form_body_decodes_percent_encoded_values
      body = "oauth_consumer_key=key%2B123&oauth_signature=sig%3D%26value"
      parsed = SimpleOAuth::Header.parse_form_body(body)

      assert_equal "key+123", parsed[:consumer_key]
      assert_equal "sig=&value", parsed[:signature]
    end

    def test_parse_form_body_handles_empty_values
      body = "oauth_consumer_key=key123&oauth_callback=&oauth_token=token456"
      parsed = SimpleOAuth::Header.parse_form_body(body)

      assert_equal "", parsed[:callback]
    end

    def test_parse_form_body_strips_oauth_prefix_from_keys
      body = "oauth_consumer_key=key123&oauth_signature_method=HMAC-SHA1"
      parsed = SimpleOAuth::Header.parse_form_body(body)

      assert parsed.key?(:consumer_key)
      assert parsed.key?(:signature_method)
      refute parsed.key?(:oauth_consumer_key)
      refute parsed.key?(:oauth_signature_method)
    end

    def test_parse_form_body_returns_empty_hash_for_empty_body
      parsed = SimpleOAuth::Header.parse_form_body("")

      assert_equal({}, parsed)
    end

    def test_parse_form_body_returns_empty_hash_for_body_without_oauth_params
      body = "status=hello&text=world"
      parsed = SimpleOAuth::Header.parse_form_body(body)

      assert_equal({}, parsed)
    end

    def test_parse_form_body_handles_all_standard_oauth_parameters
      body = "oauth_consumer_key=ck&oauth_token=tk&oauth_signature_method=HMAC-SHA1&" \
             "oauth_signature=sig&oauth_timestamp=123456&oauth_nonce=abc&" \
             "oauth_version=1.0&oauth_callback=http%3A%2F%2Fexample.com&oauth_verifier=ver"
      parsed = SimpleOAuth::Header.parse_form_body(body)

      assert_equal "ck", parsed[:consumer_key]
      assert_equal "tk", parsed[:token]
      assert_equal "HMAC-SHA1", parsed[:signature_method]
      assert_equal "sig", parsed[:signature]
      assert_equal "123456", parsed[:timestamp]
      assert_equal "abc", parsed[:nonce]
      assert_equal "1.0", parsed[:version]
      assert_equal "http://example.com", parsed[:callback]
      assert_equal "ver", parsed[:verifier]
    end

    def test_parse_form_body_handles_plus_signs_as_spaces
      body = "oauth_consumer_key=key+with+spaces"
      parsed = SimpleOAuth::Header.parse_form_body(body)

      assert_equal "key with spaces", parsed[:consumer_key]
    end

    def test_parse_form_body_calls_to_s_on_input
      body = Object.new
      def body.to_s
        "oauth_consumer_key=key123"
      end

      parsed = SimpleOAuth::Header.parse_form_body(body)

      assert_equal "key123", parsed[:consumer_key]
    end

    def test_parse_form_body_uses_first_value_for_duplicate_keys
      body = "oauth_consumer_key=first&oauth_consumer_key=second"
      parsed = SimpleOAuth::Header.parse_form_body(body)

      assert_equal "first", parsed[:consumer_key]
    end

    def test_parse_form_body_handles_key_without_equals_sign
      # CGI.parse returns empty array for keys without '=', we should return empty string
      body = "oauth_callback&oauth_consumer_key=key123"
      parsed = SimpleOAuth::Header.parse_form_body(body)

      assert_equal "", parsed[:callback]
      assert_equal "key123", parsed[:consumer_key]
    end

    def test_parse_form_body_ignores_invalid_oauth_keys
      # Only valid OAuth keys (PARSE_KEYS) should be extracted
      body = "oauth_consumer_key=key123&oauth_invalid_key=bad&oauth_signature=sig"
      parsed = SimpleOAuth::Header.parse_form_body(body)

      assert_equal 2, parsed.keys.size
      assert_equal "key123", parsed[:consumer_key]
      assert_equal "sig", parsed[:signature]
      refute parsed.key?(:invalid_key)
    end

    def test_parse_form_body_requires_oauth_prefix
      # Keys without oauth_ prefix should not be extracted, even if they match PARSE_KEYS names
      # Important: non-prefixed key comes AFTER prefixed key to ensure it wouldn't overwrite
      body = "oauth_consumer_key=real&consumer_key=sneaky"
      parsed = SimpleOAuth::Header.parse_form_body(body)

      assert_equal 1, parsed.keys.size
      assert_equal "real", parsed[:consumer_key]
    end

    # Integration tests - using parsed form body for validation

    def test_header_can_be_created_from_parsed_form_body
      secrets = {consumer_secret: "CONSUMER_SECRET", token_secret: "TOKEN_SECRET"}
      original_header = SimpleOAuth::Header.new(:post, "https://api.example.com/resource", {}, secrets)

      # Simulate form body containing OAuth params (as a server would receive)
      form_body = original_header.signed_attributes.map { |k, v|
        "#{k}=#{SimpleOAuth::Header.escape(v)}"
      }.join("&")

      parsed_oauth = SimpleOAuth::Header.parse_form_body(form_body)
      reconstructed_header = SimpleOAuth::Header.new(:post, "https://api.example.com/resource", {}, parsed_oauth)

      assert reconstructed_header.valid?(secrets)
    end

    def test_parsed_form_body_validation_with_request_params
      secrets = {consumer_secret: "CONSUMER_SECRET", token_secret: "TOKEN_SECRET"}
      request_params = {status: "Hello world!"}
      original_header = SimpleOAuth::Header.new(:post, "https://api.example.com/update", request_params, secrets)

      # Build form body with both OAuth params and request params
      oauth_params = original_header.signed_attributes.map { |k, v|
        "#{k}=#{SimpleOAuth::Header.escape(v)}"
      }.join("&")
      request_param_str = request_params.map { |k, v|
        "#{k}=#{SimpleOAuth::Header.escape(v)}"
      }.join("&")
      form_body = "#{oauth_params}&#{request_param_str}"

      parsed_oauth = SimpleOAuth::Header.parse_form_body(form_body)
      reconstructed_header = SimpleOAuth::Header.new(:post, "https://api.example.com/update", request_params, parsed_oauth)

      assert reconstructed_header.valid?(secrets)
    end
  end
end
