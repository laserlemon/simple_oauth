require "test_helper"

module SimpleOAuth
  class HeaderParseBasicTest < Minitest::Test
    cover "SimpleOAuth::Header*"

    def test_parse_returns_a_hash
      header = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friends/list.json", {})
      parsed_options = SimpleOAuth::Header.parse(header)

      assert_kind_of Hash, parsed_options
    end

    def test_parse_includes_options_used_to_build_header
      header = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friends/list.json", {})
      parsed_options = SimpleOAuth::Header.parse(header)

      assert_equal header.options, parsed_options.except(:signature)
    end

    def test_parse_header_options_does_not_include_signature
      header = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friends/list.json", {})

      refute header.options.key?(:signature)
    end

    def test_parse_includes_signature_in_parsed_options
      header = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friends/list.json", {})
      parsed_options = SimpleOAuth::Header.parse(header)

      assert parsed_options.key?(:signature)
    end

    def test_parse_has_non_nil_signature
      header = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friends/list.json", {})
      parsed_options = SimpleOAuth::Header.parse(header)

      refute_nil parsed_options[:signature]
    end

    def test_parse_handles_empty_value
      header_with_empty = 'OAuth oauth_callback=""'
      parsed = SimpleOAuth::Header.parse(header_with_empty)

      assert_equal "", parsed[:callback]
    end

    def test_parse_strips_oauth_prefix_from_keys
      header = 'OAuth oauth_consumer_key="key123"'
      parsed = SimpleOAuth::Header.parse(header)

      assert parsed.key?(:consumer_key)
      refute parsed.key?(:oauth_consumer_key)
    end

    def test_parse_silently_ignores_params_without_oauth_prefix
      header = 'OAuth consumer_key="key123"'
      parsed = SimpleOAuth::Header.parse(header)

      assert_empty(parsed)
    end
  end

  class HeaderParseWhitespaceTest < Minitest::Test
    cover "SimpleOAuth::Header*"

    def test_parse_parses_header_with_spaces_after_commas
      header_with_spaces = 'OAuth oauth_consumer_key="abcd", oauth_nonce="oLKtec51GQy", ' \
                           'oauth_signature="efgh%26mnop", oauth_signature_method="PLAINTEXT", ' \
                           'oauth_timestamp="1286977095", oauth_token="ijkl", oauth_version="1.0"'
      parsed = SimpleOAuth::Header.parse(header_with_spaces)

      assert_equal 7, parsed.keys.size
    end

    def test_parse_parses_header_with_multiple_spaces_after_commas
      header_with_tabs = 'OAuth oauth_consumer_key="abcd", oauth_nonce="oLKtec51GQy",  ' \
                         'oauth_signature="efgh%26mnop",  oauth_signature_method="PLAINTEXT", ' \
                         'oauth_timestamp="1286977095", oauth_token="ijkl", oauth_version="1.0"'
      parsed = SimpleOAuth::Header.parse(header_with_tabs)

      assert_equal 7, parsed.keys.size
    end

    def test_parse_parses_header_with_mixed_whitespace_after_commas
      header_with_spaces_and_tabs = 'OAuth oauth_consumer_key="abcd",  oauth_nonce="oLKtec51GQy",   ' \
                                    'oauth_signature="efgh%26mnop",   oauth_signature_method="PLAINTEXT",  ' \
                                    'oauth_timestamp="1286977095",  oauth_token="ijkl",  oauth_version="1.0"'
      parsed = SimpleOAuth::Header.parse(header_with_spaces_and_tabs)

      assert_equal 7, parsed.keys.size
    end

    def test_parse_parses_header_without_spaces_after_commas
      header_without_spaces = 'OAuth oauth_consumer_key="abcd",oauth_nonce="oLKtec51GQy",' \
                              'oauth_signature="efgh%26mnop",oauth_signature_method="PLAINTEXT",' \
                              'oauth_timestamp="1286977095",oauth_token="ijkl",oauth_version="1.0"'
      parsed = SimpleOAuth::Header.parse(header_without_spaces)

      assert_equal 7, parsed.keys.size
    end

    def test_parse_handles_trailing_whitespace_after_comma
      header = 'OAuth oauth_consumer_key="key123",   '
      parsed = SimpleOAuth::Header.parse(header)

      assert_equal "key123", parsed[:consumer_key]
    end

    def test_parse_handles_multiple_spaces_after_oauth
      header = 'OAuth   oauth_consumer_key="key123"'
      parsed = SimpleOAuth::Header.parse(header)

      assert_equal "key123", parsed[:consumer_key]
    end
  end

  class HeaderParseFilteringTest < Minitest::Test
    cover "SimpleOAuth::Header*"

    def test_parse_ignores_unrecognized_oauth_keys_count
      header = 'OAuth oauth_consumer_key="key123", oauth_invalid_key="bad", oauth_signature="sig"'
      parsed = SimpleOAuth::Header.parse(header)

      assert_equal 2, parsed.keys.size
    end

    def test_parse_ignores_unrecognized_oauth_keys_values
      header = 'OAuth oauth_consumer_key="key123", oauth_invalid_key="bad", oauth_signature="sig"'
      parsed = SimpleOAuth::Header.parse(header)

      assert_equal "key123", parsed[:consumer_key]
      assert_equal "sig", parsed[:signature]
    end

    def test_parse_ignores_unrecognized_oauth_keys_exclusion
      header = 'OAuth oauth_consumer_key="key123", oauth_invalid_key="bad", oauth_signature="sig"'
      parsed = SimpleOAuth::Header.parse(header)

      refute parsed.key?(:invalid_key)
    end

    def test_parse_ignores_non_oauth_prefixed_keys_count
      header = 'OAuth oauth_consumer_key="key123", custom_key="ignored", oauth_signature="sig"'
      parsed = SimpleOAuth::Header.parse(header)

      assert_equal 2, parsed.keys.size
    end

    def test_parse_ignores_non_oauth_prefixed_keys_values
      header = 'OAuth oauth_consumer_key="key123", custom_key="ignored", oauth_signature="sig"'
      parsed = SimpleOAuth::Header.parse(header)

      assert_equal "key123", parsed[:consumer_key]
      assert_equal "sig", parsed[:signature]
    end

    def test_parse_ignores_non_oauth_prefixed_keys_exclusion
      header = 'OAuth oauth_consumer_key="key123", custom_key="ignored", oauth_signature="sig"'
      parsed = SimpleOAuth::Header.parse(header)

      refute parsed.key?(:custom_key)
    end

    def test_parse_handles_unescaped_comma_in_value
      header = 'OAuth oauth_consumer_key="key,with,commas", oauth_signature="sig"'
      parsed = SimpleOAuth::Header.parse(header)

      assert_equal "key,with,commas", parsed[:consumer_key]
      assert_equal "sig", parsed[:signature]
    end
  end

  class HeaderParseErrorTest < Minitest::Test
    cover "SimpleOAuth::Header*"

    def test_parse_raises_on_malformed_pair_position
      header_with_malformed = 'OAuth oauth_consumer_key="key123", malformed_without_quotes, oauth_token="token456"'

      error = assert_raises(SimpleOAuth::ParseError) do
        SimpleOAuth::Header.parse(header_with_malformed)
      end
      assert_match(/Could not parse parameter at position 35/, error.message)
    end

    def test_parse_raises_on_malformed_pair_content
      header_with_malformed = 'OAuth oauth_consumer_key="key123", malformed_without_quotes, oauth_token="token456"'

      error = assert_raises(SimpleOAuth::ParseError) do
        SimpleOAuth::Header.parse(header_with_malformed)
      end
      assert_match(/malformed_without_quotes/, error.message)
    end

    def test_parse_raises_on_malformed_pair_inspect_format
      header_with_malformed = 'OAuth oauth_consumer_key="key123", malformed_without_quotes, oauth_token="token456"'

      error = assert_raises(SimpleOAuth::ParseError) do
        SimpleOAuth::Header.parse(header_with_malformed)
      end
      # Verify .inspect is used (shows escaped quotes)
      assert_match(/\\"token456\\"/, error.message)
    end

    def test_parse_raises_on_missing_opening_quote_position
      header_with_malformed = "OAuth oauth_consumer_key=key123"

      error = assert_raises(SimpleOAuth::ParseError) do
        SimpleOAuth::Header.parse(header_with_malformed)
      end
      assert_match(/Could not parse parameter at position 6/, error.message)
    end

    def test_parse_raises_on_missing_opening_quote_inspect_format
      header_with_malformed = "OAuth oauth_consumer_key=key123"

      error = assert_raises(SimpleOAuth::ParseError) do
        SimpleOAuth::Header.parse(header_with_malformed)
      end
      # Verify .inspect is used (shows surrounding quotes on the string)
      assert_match(/"oauth_consumer_key=key123"/, error.message)
    end

    def test_parse_raises_on_missing_comma_position
      header = 'OAuth oauth_consumer_key="key123" oauth_signature="sig"'

      error = assert_raises(SimpleOAuth::ParseError) do
        SimpleOAuth::Header.parse(header)
      end
      assert_match(/Expected comma after 'oauth_consumer_key' parameter at position 34/, error.message)
    end

    def test_parse_raises_on_missing_comma_content
      header = 'OAuth oauth_consumer_key="key123" oauth_signature="sig"'

      error = assert_raises(SimpleOAuth::ParseError) do
        SimpleOAuth::Header.parse(header)
      end
      assert_match(/oauth_signature/, error.message)
    end

    def test_parse_raises_on_missing_comma_inspect_format
      header = 'OAuth oauth_consumer_key="key123" oauth_signature="sig"'

      error = assert_raises(SimpleOAuth::ParseError) do
        SimpleOAuth::Header.parse(header)
      end
      # Verify .inspect is used (shows escaped quotes)
      assert_match(/\\"sig\\"/, error.message)
    end

    def test_parse_raises_on_missing_oauth_header_prefix
      header = 'oauth_consumer_key="key123"'

      error = assert_raises(SimpleOAuth::ParseError) do
        SimpleOAuth::Header.parse(header)
      end
      assert_match(/Authorization header must start with 'OAuth '/, error.message)
    end

    def test_parse_raises_on_completely_invalid_header
      header = "Bearer token123"

      error = assert_raises(SimpleOAuth::ParseError) do
        SimpleOAuth::Header.parse(header)
      end
      assert_match(/Authorization header must start with 'OAuth '/, error.message)
    end
  end
end
