require "test_helper"

module SimpleOAuth
  class HeaderParseTest < Minitest::Test
    cover "SimpleOAuth::Header*"

    # .parse tests

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

    def test_parse_skips_malformed_pairs
      header_with_malformed = 'OAuth oauth_consumer_key="key123", malformed_without_quotes, oauth_token="token456"'
      parsed = SimpleOAuth::Header.parse(header_with_malformed)

      assert_equal 2, parsed.keys.size
      assert_equal "key123", parsed[:consumer_key]
      assert_equal "token456", parsed[:token]
    end

    def test_parse_skips_multiple_malformed_pairs
      header_with_malformed = 'OAuth invalid1, oauth_consumer_key="key", invalid2, oauth_token="tok", invalid3'
      parsed = SimpleOAuth::Header.parse(header_with_malformed)

      assert_equal 2, parsed.keys.size
      assert_equal "key", parsed[:consumer_key]
      assert_equal "tok", parsed[:token]
    end
  end
end
