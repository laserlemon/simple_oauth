require "test_helper"

module SimpleOAuth
  # Tests for Header instance methods using RFC 5849 examples.
  class HeaderInstanceTest < Minitest::Test
    include TestHelpers

    cover "SimpleOAuth::Header*"

    # RFC 5849 Section 3.4.1.2 - Base String URI construction
    # Uses example URLs from the spec for normalization tests

    # #initialize tests

    def test_initialize_stringifies_and_uppercases_request_method
      # RFC 5849 Section 3.4.1.1 - HTTP request method MUST be uppercase
      header = SimpleOAuth::Header.new(:get, "HTTPS://PHOTOS.example.net:443/photos?file=vacation.jpg#anchor", {})

      assert_equal "GET", header.method
    end

    def test_initialize_downcases_scheme_and_authority
      # RFC 5849 Section 3.4.1.2 - scheme and host are case-insensitive, normalized to lowercase
      header = SimpleOAuth::Header.new(:get, "HTTPS://PHOTOS.Example.Net:443/photos?file=vacation.jpg#anchor", {})

      assert_match %r{^https://photos\.example\.net/}, header.url
    end

    def test_initialize_ignores_query_and_fragment
      # RFC 5849 Section 3.4.1.2 - query and fragment excluded from base string URI
      header = SimpleOAuth::Header.new(:get, "HTTPS://PHOTOS.Example.Net:443/photos?file=vacation.jpg#anchor", {})

      assert_match %r{/photos$}, header.url
    end

    def test_initialize_stores_downcased_scheme_in_uri
      header = SimpleOAuth::Header.new(:get, "HTTPS://photos.example.net/photos", {})

      assert header.url.start_with?("https://")
    end

    def test_scheme_is_downcased_from_mixed_case
      header = SimpleOAuth::Header.new(:get, "HtTpS://photos.example.net/photos", {})

      refute_includes header.url, "HtTpS"
      assert_includes header.url, "https"
    end

    def test_initialize_accepts_object_with_to_s_method
      url_object = Object.new
      url_object.define_singleton_method(:to_s) { "https://photos.example.net/photos" }
      header = SimpleOAuth::Header.new(:get, url_object, {})

      assert_equal "https://photos.example.net/photos", header.url
    end

    def test_initialize_with_hash_subclass_uses_default_options
      class_with_hash_ancestor = Class.new(Hash)
      options = class_with_hash_ancestor.new
      options[:consumer_key] = RFC5849::CONSUMER_KEY

      header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos", {}, options)

      assert header.options.key?(:nonce)
      assert header.options.key?(:timestamp)
    end

    def test_initialize_converts_string_keys_to_symbols
      options = {"consumer_key" => RFC5849::CONSUMER_KEY, "consumer_secret" => RFC5849::CONSUMER_SECRET}

      header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos", {}, options)

      assert header.options.key?(:consumer_key)
      assert header.options.key?(:consumer_secret)
    end

    def test_initialize_preserves_values_when_converting_string_keys
      options = {"consumer_key" => RFC5849::CONSUMER_KEY, "consumer_secret" => RFC5849::CONSUMER_SECRET}

      header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos", {}, options)

      assert_equal RFC5849::CONSUMER_KEY, header.options[:consumer_key]
      assert_equal RFC5849::CONSUMER_SECRET, header.options[:consumer_secret]
    end

    # #normalized_attributes tests

    def test_normalized_attributes_returns_sorted_quoted_comma_separated_list
      header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos", {})
      stubbed_attrs = {d: 1, c: 2, b: 3, a: 4}
      header.define_singleton_method(:signed_attributes) { stubbed_attrs }

      assert_equal 'a="4", b="3", c="2", d="1"', header.send(:normalized_attributes)
    end

    def test_normalized_attributes_uri_encodes_values
      header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos", {})
      stubbed_attrs = {1 => "!", 2 => "@", 3 => "#", 4 => "$"}
      header.define_singleton_method(:signed_attributes) { stubbed_attrs }

      assert_equal '1="%21", 2="%40", 3="%23", 4="%24"', header.send(:normalized_attributes)
    end

    def test_normalized_attributes_converts_symbol_keys_to_strings_for_sorting
      header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos", {})
      stubbed_attrs = {z_key: "z", a_key: "a"}
      header.define_singleton_method(:signed_attributes) { stubbed_attrs }

      result = header.send(:normalized_attributes)

      assert_match(/^a_key=.*z_key=/, result)
    end

    # #signed_attributes tests

    def test_signed_attributes_includes_oauth_signature
      header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos", {})

      assert header.send(:signed_attributes).key?(:oauth_signature)
    end

    # #secret tests

    def test_secret_combines_consumer_and_token_secrets_with_ampersand
      # RFC 5849 Section 3.4.2 - HMAC-SHA1 key is consumer_secret&token_secret
      header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos", {},
        consumer_secret: RFC5849::CONSUMER_SECRET, token_secret: RFC5849::TOKEN_SECRET)

      assert_equal "#{RFC5849::CONSUMER_SECRET}&#{RFC5849::TOKEN_SECRET}", header.send(:secret)
    end

    def test_secret_uri_encodes_each_value_before_combination
      # Secrets with special characters should be percent-encoded
      header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos", {},
        consumer_secret: "CONSUM#R_SECRET", token_secret: "TOKEN_S#CRET")

      assert_equal "CONSUM%23R_SECRET&TOKEN_S%23CRET", header.send(:secret)
    end

    # #signature_base tests

    def test_signature_base_combines_method_url_and_params_with_ampersands
      # RFC 5849 Section 3.4.1 - signature base string format
      header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos", {})
      header.define_singleton_method(:method) { "METHOD" }
      header.define_singleton_method(:url) { "URL" }
      header.define_singleton_method(:normalized_params) { "NORMALIZED_PARAMS" }

      assert_equal "METHOD&URL&NORMALIZED_PARAMS", header.send(:signature_base)
    end

    def test_signature_base_uri_encodes_each_value
      header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos", {})
      header.define_singleton_method(:method) { "ME#HOD" }
      header.define_singleton_method(:url) { "U#L" }
      header.define_singleton_method(:normalized_params) { "NORMAL#ZED_PARAMS" }

      assert_equal "ME%23HOD&U%23L&NORMAL%23ZED_PARAMS", header.send(:signature_base)
    end
  end
end
