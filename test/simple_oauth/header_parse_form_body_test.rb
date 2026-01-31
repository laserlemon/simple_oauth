require "test_helper"

module SimpleOAuth
  class HeaderParseFormBodyBasicTest < Minitest::Test
    cover "SimpleOAuth::Header*"

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
      body = "oauth_callback&oauth_consumer_key=key123"
      parsed = SimpleOAuth::Header.parse_form_body(body)

      assert_equal "", parsed[:callback]
      assert_equal "key123", parsed[:consumer_key]
    end
  end

  class HeaderParseFormBodyFilteringTest < Minitest::Test
    cover "SimpleOAuth::Header*"

    def test_parse_form_body_ignores_non_oauth_parameters_count
      body = "oauth_consumer_key=key123&status=hello%20world&oauth_token=token456"
      parsed = SimpleOAuth::Header.parse_form_body(body)

      assert_equal 2, parsed.keys.size
    end

    def test_parse_form_body_ignores_non_oauth_parameters_values
      body = "oauth_consumer_key=key123&status=hello%20world&oauth_token=token456"
      parsed = SimpleOAuth::Header.parse_form_body(body)

      assert_equal "key123", parsed[:consumer_key]
      assert_equal "token456", parsed[:token]
    end

    def test_parse_form_body_excludes_non_oauth_key
      body = "oauth_consumer_key=key123&status=hello%20world&oauth_token=token456"
      parsed = SimpleOAuth::Header.parse_form_body(body)

      refute parsed.key?(:status)
    end

    def test_parse_form_body_strips_oauth_prefix_includes_correct_keys
      body = "oauth_consumer_key=key123&oauth_signature_method=HMAC-SHA1"
      parsed = SimpleOAuth::Header.parse_form_body(body)

      assert parsed.key?(:consumer_key)
      assert parsed.key?(:signature_method)
    end

    def test_parse_form_body_strips_oauth_prefix_excludes_prefixed_keys
      body = "oauth_consumer_key=key123&oauth_signature_method=HMAC-SHA1"
      parsed = SimpleOAuth::Header.parse_form_body(body)

      refute parsed.key?(:oauth_consumer_key)
      refute parsed.key?(:oauth_signature_method)
    end

    def test_parse_form_body_returns_empty_hash_for_empty_body
      parsed = SimpleOAuth::Header.parse_form_body("")

      assert_empty parsed
    end

    def test_parse_form_body_returns_empty_hash_for_body_without_oauth_params
      body = "status=hello&text=world"
      parsed = SimpleOAuth::Header.parse_form_body(body)

      assert_empty parsed
    end

    def test_parse_form_body_ignores_invalid_oauth_keys_count
      body = "oauth_consumer_key=key123&oauth_invalid_key=bad&oauth_signature=sig"
      parsed = SimpleOAuth::Header.parse_form_body(body)

      assert_equal 2, parsed.keys.size
    end

    def test_parse_form_body_ignores_invalid_oauth_keys_values
      body = "oauth_consumer_key=key123&oauth_invalid_key=bad&oauth_signature=sig"
      parsed = SimpleOAuth::Header.parse_form_body(body)

      assert_equal "key123", parsed[:consumer_key]
      assert_equal "sig", parsed[:signature]
    end

    def test_parse_form_body_ignores_invalid_oauth_keys_exclusion
      body = "oauth_consumer_key=key123&oauth_invalid_key=bad&oauth_signature=sig"
      parsed = SimpleOAuth::Header.parse_form_body(body)

      refute parsed.key?(:invalid_key)
    end

    def test_parse_form_body_requires_oauth_prefix
      body = "oauth_consumer_key=real&consumer_key=sneaky"
      parsed = SimpleOAuth::Header.parse_form_body(body)

      assert_equal 1, parsed.keys.size
      assert_equal "real", parsed[:consumer_key]
    end
  end

  class HeaderParseFormBodyStandardParamsTest < Minitest::Test
    cover "SimpleOAuth::Header*"

    def setup
      @body = "oauth_consumer_key=ck&oauth_token=tk&oauth_signature_method=HMAC-SHA1&" \
              "oauth_signature=sig&oauth_timestamp=123456&oauth_nonce=abc&" \
              "oauth_version=1.0&oauth_callback=http%3A%2F%2Fexample.com&oauth_verifier=ver"
      @parsed = SimpleOAuth::Header.parse_form_body(@body)
    end

    def test_parses_consumer_key
      assert_equal "ck", @parsed[:consumer_key]
    end

    def test_parses_token
      assert_equal "tk", @parsed[:token]
    end

    def test_parses_signature_method
      assert_equal "HMAC-SHA1", @parsed[:signature_method]
    end

    def test_parses_signature
      assert_equal "sig", @parsed[:signature]
    end

    def test_parses_timestamp
      assert_equal "123456", @parsed[:timestamp]
    end

    def test_parses_nonce
      assert_equal "abc", @parsed[:nonce]
    end

    def test_parses_version
      assert_equal "1.0", @parsed[:version]
    end

    def test_parses_and_decodes_callback
      assert_equal "http://example.com", @parsed[:callback]
    end

    def test_parses_verifier
      assert_equal "ver", @parsed[:verifier]
    end
  end

  class HeaderParseFormBodyIntegrationTest < Minitest::Test
    cover "SimpleOAuth::Header*"

    def test_header_can_be_created_from_parsed_form_body
      secrets = {consumer_secret: "CONSUMER_SECRET", token_secret: "TOKEN_SECRET"}
      original_header = SimpleOAuth::Header.new(:post, "https://api.example.com/resource", {}, secrets)
      form_body = build_form_body(original_header.signed_attributes)

      parsed_oauth = SimpleOAuth::Header.parse_form_body(form_body)
      reconstructed_header = SimpleOAuth::Header.new(:post, "https://api.example.com/resource", {}, parsed_oauth)

      assert reconstructed_header.valid?(secrets)
    end

    def test_parsed_form_body_validation_with_request_params
      secrets = {consumer_secret: "CONSUMER_SECRET", token_secret: "TOKEN_SECRET"}
      request_params = {status: "Hello world!"}
      original_header = SimpleOAuth::Header.new(:post, "https://api.example.com/update", request_params, secrets)
      form_body = build_form_body(original_header.signed_attributes.merge(request_params))

      parsed_oauth = SimpleOAuth::Header.parse_form_body(form_body)
      reconstructed_header = SimpleOAuth::Header.new(:post, "https://api.example.com/update", request_params, parsed_oauth)

      assert reconstructed_header.valid?(secrets)
    end

    private

    def build_form_body(params)
      params.map do |k, v|
        "#{k}=#{SimpleOAuth::Header.escape(v)}"
      end.join("&")
    end
  end
end
