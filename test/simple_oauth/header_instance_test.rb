require "test_helper"

module SimpleOAuth
  class HeaderInstanceTest < Minitest::Test
    include TestHelpers

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

    # #private_key tests

    def test_private_key_returns_rsa_private_key_from_consumer_secret
      header = SimpleOAuth::Header.new(:get, "https://example.com", {}, consumer_secret: rsa_private_key)

      assert_kind_of OpenSSL::PKey::RSA, header.send(:private_key)
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
