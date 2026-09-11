require "test_helper"

module SimpleOAuth
  # Tests for the query parameters that are signed, per RFC 5849 Section 3.4.1.3.
  class HeaderURLParamsTest < Minitest::Test
    include TestHelpers

    cover "SimpleOAuth::Header*"

    # #url_params tests
    def test_url_params_returns_empty_array_when_no_query_parameters
      header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos", {})

      assert_empty header.send(:url_params)
    end

    def test_url_params_returns_key_value_pairs_for_query_parameters
      # RFC 5849 Section 1.2 - file and size query parameters
      header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos?file=vacation.jpg", {})

      assert_equal [%w[file vacation.jpg]], header.send(:url_params)
    end

    def test_url_params_sorts_values_for_repeated_keys
      # RFC 5849 Section 3.4.1.3.2 - values for same key sorted
      header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos?size=3&size=1&size=2", {})

      assert_equal [%w[size 1], %w[size 2], %w[size 3]], header.send(:url_params)
    end

    def test_url_params_handles_empty_query_string
      header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos?", {})

      assert_empty header.send(:url_params)
    end

    def test_normalized_params_sorts_params_alphabetically
      # RFC 5849 Section 3.4.1.3.2 - parameters sorted by name
      header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos", {})
      header.define_singleton_method(:signature_params) { [%w[z last], %w[a first], %w[m middle]] }
      result = header.send(:normalized_params)

      assert_equal "a=first&m=middle&z=last", result
    end

    def test_url_params_accumulates_multiple_keys
      # RFC 5849 Section 1.2 - multiple query parameters
      header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos?file=vacation.jpg&size=original", {})
      url_params = header.send(:url_params)
      expected = [%w[file vacation.jpg], %w[size original]]

      assert_equal expected, url_params.sort
    end

    def test_normalized_params_escapes_special_characters_in_keys
      # RFC 5849 Section 3.6 - percent-encoding
      header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos", {})
      header.define_singleton_method(:signature_params) { [["a[]", "value"]] }
      result = header.send(:normalized_params)

      assert_equal "a%5B%5D=value", result
    end

    def test_normalized_params_escapes_special_characters_in_values
      # RFC 5849 Section 3.6 - percent-encoding
      header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos", {})
      header.define_singleton_method(:signature_params) { [["key", "value with spaces"]] }
      result = header.send(:normalized_params)

      assert_equal "key=value%20with%20spaces", result
    end

    def test_params_are_included_in_signature_calculation
      # Verify that params passed to initialize affect the signature
      header1 = SimpleOAuth::Header.new(:post, "https://photos.example.net/photos", {status: "Hello"},
        consumer_key: RFC5849::CONSUMER_KEY, consumer_secret: RFC5849::CONSUMER_SECRET,
        nonce: "chapoH", timestamp: "137131202")
      header2 = SimpleOAuth::Header.new(:post, "https://photos.example.net/photos", {status: "Goodbye"},
        consumer_key: RFC5849::CONSUMER_KEY, consumer_secret: RFC5849::CONSUMER_SECRET,
        nonce: "chapoH", timestamp: "137131202")

      refute_equal header1.signed_attributes[:oauth_signature], header2.signed_attributes[:oauth_signature]
    end

    def test_params_accessor_returns_initialized_params
      params = {status: "Hello", count: "5"}
      header = SimpleOAuth::Header.new(:post, "https://photos.example.net/photos", params,
        consumer_key: RFC5849::CONSUMER_KEY, consumer_secret: RFC5849::CONSUMER_SECRET)

      assert_equal params, header.params
    end
  end
end
