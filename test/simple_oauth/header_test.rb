require "test_helper"

module SimpleOAuth
  class HeaderTest < Minitest::Test
    include TestHelpers

    # .default_options tests

    def test_default_options_is_different_every_time
      first = SimpleOAuth::Header.default_options
      second = SimpleOAuth::Header.default_options

      refute_equal first, second
    end

    def test_default_options_is_used_for_new_headers
      # Create a header and verify its options match default_options structure
      header = SimpleOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friendships.json", {})

      assert header.options.key?(:nonce)
      assert header.options.key?(:signature_method)
      assert header.options.key?(:timestamp)
      assert header.options.key?(:version)
    end

    def test_default_options_includes_signature_method
      refute_nil SimpleOAuth::Header.default_options[:signature_method]
    end

    def test_default_options_includes_oauth_version
      refute_nil SimpleOAuth::Header.default_options[:version]
    end

    # .escape tests

    def test_escape_escapes_non_word_characters
      [" ", "!", "@", "#", "$", "%", "^", "&"].each do |character|
        escaped = SimpleOAuth::Header.escape(character)

        refute_equal character, escaped
        assert_equal URI::RFC2396_PARSER.escape(character, /.*/), escaped
      end
    end

    def test_escape_does_not_escape_dash_dot_or_tilde
      ["-", ".", "~"].each do |character|
        escaped = SimpleOAuth::Header.escape(character)

        assert_equal character, escaped
      end
    end

    def test_escape_escapes_non_ascii_characters
      assert_equal "%C3%A9", SimpleOAuth::Header.escape("é")
    end

    def test_escape_escapes_multibyte_characters
      assert_equal "%E3%81%82", SimpleOAuth::Header.escape("あ")
    end

    # .unescape tests

    def test_unescape_unescapes_percent_encoded_characters
      assert_equal "é", SimpleOAuth::Header.unescape("%C3%A9")
    end

    def test_unescape_unescapes_multibyte_characters
      assert_equal "あ", SimpleOAuth::Header.unescape("%E3%81%82")
    end

    def test_unescape_returns_unencoded_characters_as_is
      assert_equal "hello", SimpleOAuth::Header.unescape("hello")
    end

    # .parse tests

    def test_parse_returns_a_hash
      header = SimpleOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friends.json", {})
      parsed_options = SimpleOAuth::Header.parse(header)

      assert_kind_of Hash, parsed_options
    end

    def test_parse_includes_options_used_to_build_header
      header = SimpleOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friends.json", {})
      parsed_options = SimpleOAuth::Header.parse(header)

      assert_equal header.options, parsed_options.except(:signature)
    end

    def test_parse_header_options_does_not_include_signature
      header = SimpleOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friends.json", {})

      refute header.options.key?(:signature)
    end

    def test_parse_includes_signature_in_parsed_options
      header = SimpleOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friends.json", {})
      parsed_options = SimpleOAuth::Header.parse(header)

      assert parsed_options.key?(:signature)
    end

    def test_parse_has_non_nil_signature
      header = SimpleOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friends.json", {})
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

    # #initialize tests

    def test_initialize_stringifies_and_uppercases_request_method
      header = SimpleOAuth::Header.new(:get, "HTTPS://api.TWITTER.com:443/1/statuses/friendships.json?foo=bar#anchor", {})

      assert_equal "GET", header.method
    end

    def test_initialize_downcases_scheme_and_authority
      header = SimpleOAuth::Header.new(:get, "HTTPS://api.TWITTER.com:443/1/statuses/friendships.json?foo=bar#anchor", {})

      assert_match %r{^https://api\.twitter\.com/}, header.url
    end

    def test_initialize_ignores_query_and_fragment
      header = SimpleOAuth::Header.new(:get, "HTTPS://api.TWITTER.com:443/1/statuses/friendships.json?foo=bar#anchor", {})

      assert_match %r{/1/statuses/friendships\.json$}, header.url
    end

    # #valid? tests - HMAC-SHA1

    def test_valid_hmac_sha1_is_not_valid_without_secrets
      secrets = {consumer_secret: "CONSUMER_SECRET", token_secret: "TOKEN_SECRET"}
      header = SimpleOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friends.json", {}, secrets)
      parsed_header = SimpleOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friends.json", {}, header)

      refute_predicate parsed_header, :valid?
    end

    def test_valid_hmac_sha1_is_valid_with_secrets
      secrets = {consumer_secret: "CONSUMER_SECRET", token_secret: "TOKEN_SECRET"}
      header = SimpleOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friends.json", {}, secrets)
      parsed_header = SimpleOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friends.json", {}, header)

      assert parsed_header.valid?(secrets)
    end

    # #valid? tests - RSA-SHA1

    def test_valid_rsa_sha1_raises_type_error_without_private_key
      secrets = {consumer_secret: rsa_private_key}
      header = SimpleOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friends.json", {},
        secrets.merge(signature_method: "RSA-SHA1"))
      parsed_header = SimpleOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friends.json", {}, header)
      assert_raises(TypeError) { parsed_header.valid? }
    end

    def test_valid_rsa_sha1_is_valid_with_private_key
      secrets = {consumer_secret: rsa_private_key}
      header = SimpleOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friends.json", {},
        secrets.merge(signature_method: "RSA-SHA1"))
      parsed_header = SimpleOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friends.json", {}, header)

      assert parsed_header.valid?(secrets)
    end

    # #valid? tests - PLAINTEXT

    def test_valid_plaintext_is_not_valid_without_secrets
      secrets = {consumer_secret: "CONSUMER_SECRET", token_secret: "TOKEN_SECRET"}
      header = SimpleOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friends.json", {},
        secrets.merge(signature_method: "PLAINTEXT"))
      parsed_header = SimpleOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friends.json", {}, header)

      refute_predicate parsed_header, :valid?
    end

    def test_valid_plaintext_is_valid_with_secrets
      secrets = {consumer_secret: "CONSUMER_SECRET", token_secret: "TOKEN_SECRET"}
      header = SimpleOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friends.json", {},
        secrets.merge(signature_method: "PLAINTEXT"))
      parsed_header = SimpleOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friends.json", {}, header)

      assert parsed_header.valid?(secrets)
    end

    # #normalized_attributes tests

    def test_normalized_attributes_returns_sorted_quoted_comma_separated_list
      header = SimpleOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friends.json", {})
      stubbed_attrs = {d: 1, c: 2, b: 3, a: 4}
      header.define_singleton_method(:signed_attributes) { stubbed_attrs }

      assert_equal 'a="4", b="3", c="2", d="1"', header.send(:normalized_attributes)
    end

    def test_normalized_attributes_uri_encodes_values
      header = SimpleOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friends.json", {})
      stubbed_attrs = {1 => "!", 2 => "@", 3 => "#", 4 => "$"}
      header.define_singleton_method(:signed_attributes) { stubbed_attrs }

      assert_equal '1="%21", 2="%40", 3="%23", 4="%24"', header.send(:normalized_attributes)
    end

    # #signed_attributes tests

    def test_signed_attributes_includes_oauth_signature
      header = SimpleOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friends.json", {})

      assert header.send(:signed_attributes).key?(:oauth_signature)
    end

    # #attributes tests

    def test_attributes_prepends_keys_with_oauth
      header = build_header_with_all_attribute_keys
      header.options[:ignore_extra_keys] = true

      assert(header.send(:attributes).keys.all? { |k| k.to_s =~ /^oauth_/ })
    end

    def test_attributes_has_only_symbol_keys
      header = build_header_with_all_attribute_keys
      header.options[:ignore_extra_keys] = true

      assert(header.send(:attributes).keys.all?(Symbol))
    end

    def test_attributes_excludes_invalid_keys
      header = build_header_with_all_attribute_keys
      header.options[:ignore_extra_keys] = true

      refute header.send(:attributes).key?(:oauth_other)
    end

    def test_attributes_preserves_values_for_valid_keys
      header = build_header_with_all_attribute_keys
      header.options[:ignore_extra_keys] = true

      assert(header.send(:attributes).all? { |k, v| k.to_s == "oauth_#{v.downcase}" })
    end

    def test_attributes_has_same_count_as_attribute_keys
      header = build_header_with_all_attribute_keys
      header.options[:ignore_extra_keys] = true

      assert_equal SimpleOAuth::Header::ATTRIBUTE_KEYS.size, header.send(:attributes).size
    end

    def test_attributes_raises_for_extra_keys
      header = build_header_with_all_attribute_keys
      error = assert_raises(RuntimeError) { header.send(:attributes) }
      assert_equal "SimpleOAuth: Found extra option keys not matching ATTRIBUTE_KEYS:\n  [:other]", error.message
    end

    # #signature tests - HMAC-SHA1

    def test_signature_hmac_sha1_calls_hmac_sha1_signature_once
      header = SimpleOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friends.json", {}, signature_method: "HMAC-SHA1")
      call_count = 0
      header.define_singleton_method(:hmac_sha1_signature) do
        call_count += 1
        "HMAC_SHA1_SIGNATURE"
      end
      header.send(:signature)

      assert_equal 1, call_count
    end

    def test_signature_hmac_sha1_returns_hmac_sha1_signature
      header = SimpleOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friends.json", {}, signature_method: "HMAC-SHA1")
      header.define_singleton_method(:hmac_sha1_signature) { "HMAC_SHA1_SIGNATURE" }

      assert_equal "HMAC_SHA1_SIGNATURE", header.send(:signature)
    end

    # #signature tests - RSA-SHA1

    def test_signature_rsa_sha1_calls_rsa_sha1_signature_once
      header = SimpleOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friends.json", {}, signature_method: "RSA-SHA1")
      call_count = 0
      header.define_singleton_method(:rsa_sha1_signature) do
        call_count += 1
        "RSA_SHA1_SIGNATURE"
      end
      header.send(:signature)

      assert_equal 1, call_count
    end

    def test_signature_rsa_sha1_returns_rsa_sha1_signature
      header = SimpleOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friends.json", {}, signature_method: "RSA-SHA1")
      header.define_singleton_method(:rsa_sha1_signature) { "RSA_SHA1_SIGNATURE" }

      assert_equal "RSA_SHA1_SIGNATURE", header.send(:signature)
    end

    # #signature tests - PLAINTEXT

    def test_signature_plaintext_calls_plaintext_signature_once
      header = SimpleOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friends.json", {}, signature_method: "PLAINTEXT")
      call_count = 0
      header.define_singleton_method(:plaintext_signature) do
        call_count += 1
        "PLAINTEXT_SIGNATURE"
      end
      header.send(:signature)

      assert_equal 1, call_count
    end

    def test_signature_plaintext_returns_plaintext_signature
      header = SimpleOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friends.json", {}, signature_method: "PLAINTEXT")
      header.define_singleton_method(:plaintext_signature) { "PLAINTEXT_SIGNATURE" }

      assert_equal "PLAINTEXT_SIGNATURE", header.send(:signature)
    end

    # #hmac_sha1_signature tests

    def test_hmac_sha1_signature_reproduces_twitter_get
      options = {
        consumer_key: "8karQBlMg6gFOwcf8kcoYw",
        consumer_secret: "3d0vcHyUiiqADpWxolW8nlDIpSWMlyK7YNgc5Qna2M",
        nonce: "547fed103e122eecf84c080843eedfe6",
        signature_method: "HMAC-SHA1",
        timestamp: "1286830180",
        token: "201425800-Sv4sTcgoffmHGkTCue0JnURT8vrm4DiFAkeFNDkh",
        token_secret: "T5qa1tF57tfDzKmpM89DHsNuhgOY4NT6DlNLsTFcuQ"
      }
      header = SimpleOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friends.json", {}, options)
      expected = 'OAuth oauth_consumer_key="8karQBlMg6gFOwcf8kcoYw", ' \
                 'oauth_nonce="547fed103e122eecf84c080843eedfe6", oauth_signature="i9CT6ahDRAlfGX3hKYf78QzXsaw%3D", ' \
                 'oauth_signature_method="HMAC-SHA1", oauth_timestamp="1286830180", ' \
                 'oauth_token="201425800-Sv4sTcgoffmHGkTCue0JnURT8vrm4DiFAkeFNDkh", oauth_version="1.0"'

      assert_equal expected, header.to_s
    end

    def test_hmac_sha1_signature_reproduces_twitter_post
      options = {
        consumer_key: "8karQBlMg6gFOwcf8kcoYw",
        consumer_secret: "3d0vcHyUiiqADpWxolW8nlDIpSWMlyK7YNgc5Qna2M",
        nonce: "b40a3e0f18590ecdcc0e273f7d7c82f8",
        signature_method: "HMAC-SHA1",
        timestamp: "1286830181",
        token: "201425800-Sv4sTcgoffmHGkTCue0JnURT8vrm4DiFAkeFNDkh",
        token_secret: "T5qa1tF57tfDzKmpM89DHsNuhgOY4NT6DlNLsTFcuQ"
      }
      header = SimpleOAuth::Header.new(:post, "https://api.twitter.com/1/statuses/update.json", {status: "hi, again"}, options)
      expected = 'OAuth oauth_consumer_key="8karQBlMg6gFOwcf8kcoYw", ' \
                 'oauth_nonce="b40a3e0f18590ecdcc0e273f7d7c82f8", oauth_signature="mPqSFKejrWWk3ZT9bTQjhO5b2xI%3D", ' \
                 'oauth_signature_method="HMAC-SHA1", oauth_timestamp="1286830181", ' \
                 'oauth_token="201425800-Sv4sTcgoffmHGkTCue0JnURT8vrm4DiFAkeFNDkh", oauth_version="1.0"'

      assert_equal expected, header.to_s
    end

    # #secret tests

    def test_secret_combines_consumer_and_token_secrets_with_ampersand
      header = SimpleOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friendships.json", {},
        consumer_secret: "CONSUMER_SECRET", token_secret: "TOKEN_SECRET")

      assert_equal "CONSUMER_SECRET&TOKEN_SECRET", header.send(:secret)
    end

    def test_secret_uri_encodes_each_value_before_combination
      header = SimpleOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friendships.json", {},
        consumer_secret: "CONSUM#R_SECRET", token_secret: "TOKEN_S#CRET")

      assert_equal "CONSUM%23R_SECRET&TOKEN_S%23CRET", header.send(:secret)
    end

    # #signature_base tests

    def test_signature_base_combines_method_url_and_params_with_ampersands
      header = SimpleOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friendships.json", {})
      header.define_singleton_method(:method) { "METHOD" }
      header.define_singleton_method(:url) { "URL" }
      header.define_singleton_method(:normalized_params) { "NORMALIZED_PARAMS" }

      assert_equal "METHOD&URL&NORMALIZED_PARAMS", header.send(:signature_base)
    end

    def test_signature_base_uri_encodes_each_value
      header = SimpleOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friendships.json", {})
      header.define_singleton_method(:method) { "ME#HOD" }
      header.define_singleton_method(:url) { "U#L" }
      header.define_singleton_method(:normalized_params) { "NORMAL#ZED_PARAMS" }

      assert_equal "ME%23HOD&U%23L&NORMAL%23ZED_PARAMS", header.send(:signature_base)
    end

    # #normalized_params tests

    def test_normalized_params_returns_a_string
      header = SimpleOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friendships.json", {})
      header.define_singleton_method(:signature_params) { [%w[A 4], %w[B 3], %w[B 2], %w[C 1], ["D[]", "0 "]] }

      assert_kind_of String, header.send(:normalized_params)
    end

    def test_normalized_params_joins_pairs_with_ampersands
      header = SimpleOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friendships.json", {})
      signature_params = [%w[A 4], %w[B 3], %w[B 2], %w[C 1], ["D[]", "0 "]]
      header.define_singleton_method(:signature_params) { signature_params }
      parts = header.send(:normalized_params).split("&")

      assert_equal signature_params.size, parts.size
    end

    def test_normalized_params_joins_key_value_with_equal_signs
      header = SimpleOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friendships.json", {})
      header.define_singleton_method(:signature_params) { [%w[A 4], %w[B 3], %w[B 2], %w[C 1], ["D[]", "0 "]] }
      pairs = header.send(:normalized_params).split("&").collect { |p| p.split("=") }

      assert(pairs.all? { |p| p.size == 2 })
    end

    # #signature_params tests

    def test_signature_params_combines_attributes_params_and_url_params
      header = SimpleOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friendships.json", {})
      header.define_singleton_method(:attributes) { {attribute: "ATTRIBUTE"} }
      header.define_singleton_method(:params) { {"param" => "PARAM"} }
      header.define_singleton_method(:url_params) { [%w[url_param 1], %w[url_param 2]] }
      expected = [[:attribute, "ATTRIBUTE"], %w[param PARAM], %w[url_param 1], %w[url_param 2]]

      assert_equal expected, header.send(:signature_params)
    end

    # #url_params tests

    def test_url_params_returns_empty_array_when_no_query_parameters
      header = SimpleOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friendships.json", {})

      assert_empty header.send(:url_params)
    end

    def test_url_params_returns_key_value_pairs_for_query_parameters
      header = SimpleOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friendships.json?test=TEST", {})

      assert_equal [%w[test TEST]], header.send(:url_params)
    end

    def test_url_params_sorts_values_for_repeated_keys
      header = SimpleOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friendships.json?test=3&test=1&test=2", {})

      assert_equal [%w[test 1], %w[test 2], %w[test 3]], header.send(:url_params)
    end

    # #rsa_sha1_signature tests

    def test_rsa_sha1_signature_reproduces_oauth_example_get
      options = {
        consumer_key: "dpf43f3p2l4k3l03",
        consumer_secret: rsa_private_key,
        nonce: "13917289812797014437",
        signature_method: "RSA-SHA1",
        timestamp: "1196666512"
      }
      header = SimpleOAuth::Header.new(:get, "http://photos.example.net/photos", {file: "vacaction.jpg", size: "original"}, options)
      expected = 'OAuth oauth_consumer_key="dpf43f3p2l4k3l03", oauth_nonce="13917289812797014437", ' \
                 'oauth_signature="jvTp%2FwX1TYtByB1m%2BPbyo0lnCOLIsyGCH7wke8AUs3BpnwZJtAuEJkvQL2%2F9n4s5wUmUl4aCI4BwpraNx4RtEXMe' \
                 '5qg5T1LVTGliMRpKasKsW%2F%2Fe%2BRinhejgCuzoH26dyF8iY2ZZ%2F5D1ilgeijhV%2FvBka5twt399mXwaYdCwFYE%3D", ' \
                 'oauth_signature_method="RSA-SHA1", oauth_timestamp="1196666512", oauth_version="1.0"'

      assert_equal expected, header.to_s
    end

    # #private_key tests

    def test_private_key_returns_rsa_private_key_from_consumer_secret
      header = SimpleOAuth::Header.new(:get, "https://example.com", {}, consumer_secret: rsa_private_key)

      assert_kind_of OpenSSL::PKey::RSA, header.send(:private_key)
    end

    # #plaintext_signature tests

    def test_plaintext_signature_reproduces_oauth_example_get
      options = {
        consumer_key: "abcd",
        consumer_secret: "efgh",
        nonce: "oLKtec51GQy",
        signature_method: "PLAINTEXT",
        timestamp: "1286977095",
        token: "ijkl",
        token_secret: "mnop"
      }
      header = SimpleOAuth::Header.new(:get, "http://host.net/resource?name=value", {name: "value"}, options)
      expected = 'OAuth oauth_consumer_key="abcd", oauth_nonce="oLKtec51GQy", oauth_signature="efgh%26mnop", ' \
                 'oauth_signature_method="PLAINTEXT", oauth_timestamp="1286977095", oauth_token="ijkl", oauth_version="1.0"'

      assert_equal expected, header.to_s
    end

    private

    def build_header_with_all_attribute_keys
      options = {}
      SimpleOAuth::Header::ATTRIBUTE_KEYS.each { |k| options[k] = k.to_s.upcase }
      options[:other] = "OTHER"
      SimpleOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friendships.json", {}, options)
    end
  end
end
