require "test_helper"

module SimpleOAuth
  # Tests for parsing OAuth Authorization headers per RFC 5849 Section 3.5.1.
  class HeaderParseBasicTest < Minitest::Test
    include TestHelpers

    cover "SimpleOAuth::Header*"

    def test_parse_returns_a_hash
      header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos", {})

      assert_kind_of Hash, SimpleOAuth::Header.parse(header)
    end

    def test_parse_includes_options_used_to_build_header
      header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos", {})
      parsed_options = SimpleOAuth::Header.parse(header)

      assert_equal header.options, parsed_options.except(:signature)
    end

    def test_parse_header_options_does_not_include_signature
      header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos", {})

      refute header.options.key?(:signature)
    end

    def test_parse_includes_signature_in_parsed_options
      header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos", {})

      assert SimpleOAuth::Header.parse(header).key?(:signature)
    end

    def test_parse_has_non_nil_signature
      header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos", {})

      refute_nil SimpleOAuth::Header.parse(header)[:signature]
    end

    def test_parse_handles_empty_value
      parsed = SimpleOAuth::Header.parse('OAuth oauth_callback=""')

      assert_equal "", parsed[:callback]
    end

    def test_parse_strips_oauth_prefix_from_keys
      parsed = SimpleOAuth::Header.parse('OAuth oauth_consumer_key="dpf43f3p2l4k3l03"')

      assert parsed.key?(:consumer_key)
      refute parsed.key?(:oauth_consumer_key)
    end

    def test_parse_silently_ignores_params_without_oauth_prefix
      parsed = SimpleOAuth::Header.parse('OAuth consumer_key="dpf43f3p2l4k3l03"')

      assert_empty parsed
    end
  end

  class HeaderParseWhitespaceTest < Minitest::Test
    include TestHelpers

    cover "SimpleOAuth::Header*"

    def test_parse_handles_spaces_after_commas
      header = 'OAuth oauth_consumer_key="dpf43f3p2l4k3l03", oauth_nonce="wIjqoS", ' \
               'oauth_signature="74KNZJeDHnMBp0EMJ9ZHt%2FXKycU%3D", oauth_signature_method="HMAC-SHA1", ' \
               'oauth_timestamp="137131200", oauth_token="hh5s93j4hdidpola", oauth_version="1.0"'

      assert_equal 7, SimpleOAuth::Header.parse(header).keys.size
    end

    def test_parse_handles_multiple_spaces_after_commas
      header = 'OAuth oauth_consumer_key="dpf43f3p2l4k3l03", oauth_nonce="wIjqoS",  ' \
               'oauth_signature="74KNZJeDHnMBp0EMJ9ZHt%2FXKycU%3D",  oauth_signature_method="HMAC-SHA1", ' \
               'oauth_timestamp="137131200", oauth_token="hh5s93j4hdidpola", oauth_version="1.0"'

      assert_equal 7, SimpleOAuth::Header.parse(header).keys.size
    end

    def test_parse_handles_no_spaces_after_commas
      header = 'OAuth oauth_consumer_key="dpf43f3p2l4k3l03",oauth_nonce="wIjqoS",' \
               'oauth_signature="74KNZJeDHnMBp0EMJ9ZHt%2FXKycU%3D",oauth_signature_method="HMAC-SHA1",' \
               'oauth_timestamp="137131200",oauth_token="hh5s93j4hdidpola",oauth_version="1.0"'

      assert_equal 7, SimpleOAuth::Header.parse(header).keys.size
    end

    def test_parse_handles_trailing_whitespace
      parsed = SimpleOAuth::Header.parse('OAuth oauth_consumer_key="dpf43f3p2l4k3l03",   ')

      assert_equal RFC5849::CONSUMER_KEY, parsed[:consumer_key]
    end

    def test_parse_handles_multiple_spaces_after_oauth_scheme
      parsed = SimpleOAuth::Header.parse('OAuth   oauth_consumer_key="dpf43f3p2l4k3l03"')

      assert_equal RFC5849::CONSUMER_KEY, parsed[:consumer_key]
    end
  end

  class HeaderParseFilteringTest < Minitest::Test
    include TestHelpers

    cover "SimpleOAuth::Header*"

    def test_parse_ignores_unrecognized_oauth_keys_count
      header = 'OAuth oauth_consumer_key="dpf43f3p2l4k3l03", oauth_invalid_key="bad", oauth_signature="sig"'
      parsed = SimpleOAuth::Header.parse(header)

      assert_equal 2, parsed.keys.size
    end

    def test_parse_ignores_unrecognized_oauth_keys_values
      header = 'OAuth oauth_consumer_key="dpf43f3p2l4k3l03", oauth_invalid_key="bad", oauth_signature="sig"'
      parsed = SimpleOAuth::Header.parse(header)

      assert_equal RFC5849::CONSUMER_KEY, parsed[:consumer_key]
      assert_equal "sig", parsed[:signature]
    end

    def test_parse_ignores_unrecognized_oauth_keys_exclusion
      header = 'OAuth oauth_consumer_key="dpf43f3p2l4k3l03", oauth_invalid_key="bad", oauth_signature="sig"'
      parsed = SimpleOAuth::Header.parse(header)

      refute parsed.key?(:invalid_key)
    end

    def test_parse_ignores_non_oauth_prefixed_keys
      header = 'OAuth oauth_consumer_key="dpf43f3p2l4k3l03", custom_key="ignored", oauth_signature="sig"'
      parsed = SimpleOAuth::Header.parse(header)

      assert_equal 2, parsed.keys.size
      refute parsed.key?(:custom_key)
    end

    def test_parse_handles_unescaped_comma_in_value
      parsed = SimpleOAuth::Header.parse('OAuth oauth_consumer_key="key,with,commas", oauth_signature="sig"')

      assert_equal "key,with,commas", parsed[:consumer_key]
      assert_equal "sig", parsed[:signature]
    end
  end

  class HeaderParseErrorTest < Minitest::Test
    include TestHelpers

    cover "SimpleOAuth::Header*"

    def test_parse_raises_on_malformed_pair_position
      header = 'OAuth oauth_consumer_key="dpf43f3p2l4k3l03", malformed_without_quotes, oauth_token="token"'

      error = assert_raises(SimpleOAuth::ParseError) { SimpleOAuth::Header.parse(header) }

      assert_match(/Could not parse parameter at position 45/, error.message)
    end

    def test_parse_raises_on_malformed_pair_content
      header = 'OAuth oauth_consumer_key="dpf43f3p2l4k3l03", malformed_without_quotes, oauth_token="token"'

      error = assert_raises(SimpleOAuth::ParseError) { SimpleOAuth::Header.parse(header) }

      assert_match(/malformed_without_quotes/, error.message)
    end

    def test_parse_raises_on_malformed_pair_inspect_format
      header = 'OAuth oauth_consumer_key="dpf43f3p2l4k3l03", malformed_without_quotes, oauth_token="token"'

      error = assert_raises(SimpleOAuth::ParseError) { SimpleOAuth::Header.parse(header) }

      # Verify .inspect is used (shows escaped quotes)
      assert_match(/\\"token\\"/, error.message)
    end

    def test_parse_raises_on_missing_opening_quote_position
      error = assert_raises(SimpleOAuth::ParseError) do
        SimpleOAuth::Header.parse("OAuth oauth_consumer_key=dpf43f3p2l4k3l03")
      end

      assert_match(/Could not parse parameter at position 6/, error.message)
    end

    def test_parse_raises_on_missing_opening_quote_inspect_format
      error = assert_raises(SimpleOAuth::ParseError) do
        SimpleOAuth::Header.parse("OAuth oauth_consumer_key=dpf43f3p2l4k3l03")
      end

      assert_match(/"oauth_consumer_key=dpf43f3p2l4k3l03"/, error.message)
    end

    def test_parse_raises_on_missing_comma_position
      header = 'OAuth oauth_consumer_key="dpf43f3p2l4k3l03" oauth_signature="sig"'

      error = assert_raises(SimpleOAuth::ParseError) { SimpleOAuth::Header.parse(header) }

      assert_match(/Expected comma after 'oauth_consumer_key' parameter at position 44/, error.message)
    end

    def test_parse_raises_on_missing_comma_content
      header = 'OAuth oauth_consumer_key="dpf43f3p2l4k3l03" oauth_signature="sig"'

      error = assert_raises(SimpleOAuth::ParseError) { SimpleOAuth::Header.parse(header) }

      assert_match(/oauth_signature/, error.message)
    end

    def test_parse_raises_on_missing_comma_inspect_format
      header = 'OAuth oauth_consumer_key="dpf43f3p2l4k3l03" oauth_signature="sig"'

      error = assert_raises(SimpleOAuth::ParseError) { SimpleOAuth::Header.parse(header) }

      assert_match(/\\"sig\\"/, error.message)
    end

    def test_parse_raises_on_missing_oauth_prefix
      error = assert_raises(SimpleOAuth::ParseError) do
        SimpleOAuth::Header.parse('oauth_consumer_key="dpf43f3p2l4k3l03"')
      end

      assert_match(/Authorization header must start with 'OAuth '/, error.message)
    end

    def test_parse_raises_on_invalid_scheme
      error = assert_raises(SimpleOAuth::ParseError) do
        SimpleOAuth::Header.parse("Bearer token123")
      end

      assert_match(/Authorization header must start with 'OAuth '/, error.message)
    end
  end
end
