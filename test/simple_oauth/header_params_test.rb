require "test_helper"

module SimpleOAuth
  # Tests for parameter normalization per RFC 5849 Section 3.4.1.3.2.
  class HeaderParamsTest < Minitest::Test
    include TestHelpers

    cover "SimpleOAuth::Header*"

    # #normalized_params tests

    def test_normalized_params_returns_a_string
      header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos", {})
      header.define_singleton_method(:signature_params) { [%w[A 4], %w[B 3], %w[B 2], %w[C 1], ["D[]", "0 "]] }

      assert_kind_of String, header.send(:normalized_params)
    end

    def test_normalized_params_joins_pairs_with_ampersands
      # RFC 5849 Section 3.4.1.3.2 - parameters joined with &
      header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos", {})
      signature_params = [%w[A 4], %w[B 3], %w[B 2], %w[C 1], ["D[]", "0 "]]
      header.define_singleton_method(:signature_params) { signature_params }
      parts = header.send(:normalized_params).split("&")

      assert_equal signature_params.size, parts.size
    end

    def test_normalized_params_joins_key_value_with_equal_signs
      # RFC 5849 Section 3.4.1.3.2 - name=value pairs
      header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos", {})
      header.define_singleton_method(:signature_params) { [%w[A 4], %w[B 3], %w[B 2], %w[C 1], ["D[]", "0 "]] }
      pairs = header.send(:normalized_params).split("&").collect { |p| p.split("=") }

      assert(pairs.all? { |p| p.size == 2 })
    end

    # #signature_params tests

    def test_signature_params_combines_attributes_params_and_url_params
      header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos", {})
      header.define_singleton_method(:attributes) { {attribute: "ATTRIBUTE"} }
      header.define_singleton_method(:params) { {"param" => "PARAM"} }
      header.define_singleton_method(:url_params) { [%w[url_param 1], %w[url_param 2]] }
      expected = [[:attribute, "ATTRIBUTE"], %w[param PARAM], %w[url_param 1], %w[url_param 2]]

      assert_equal expected, header.send(:signature_params)
    end

    def test_params_accept_repeated_keys_as_pairs
      pairs = build_header_with_fixed_credentials(:post, RFC5849::PHOTOS_URL, [%w[ids 1], %w[ids 2]])
      query = build_header_with_fixed_credentials(:post, "#{RFC5849::PHOTOS_URL}?ids=1&ids=2", {})

      assert_includes pairs.send(:normalized_params), "ids=1&ids=2"
      assert_equal query.to_s, pairs.to_s
    end

    def test_params_expand_array_values_into_repeated_pairs
      header = build_header_with_fixed_credentials(:post, RFC5849::PHOTOS_URL, {"ids" => %w[1 2]})
      pairs = build_header_with_fixed_credentials(:post, RFC5849::PHOTOS_URL, [%w[ids 1], %w[ids 2]])

      assert_includes header.send(:normalized_params), "ids=1&ids=2"
      assert_equal pairs.to_s, header.to_s
    end

    def test_params_expand_array_subclass_values
      ids = Class.new(Array).new(%w[1 2])

      assert_includes build_header(:post, RFC5849::PHOTOS_URL, {"ids" => ids}).send(:normalized_params), "ids=1&ids=2"
    end

    def test_params_with_an_empty_array_value_are_dropped
      header = build_header_with_fixed_credentials(:post, RFC5849::PHOTOS_URL, {"ids" => []})

      refute_includes header.send(:normalized_params), "ids"
    end

    def test_params_keep_single_values
      header = build_header_with_fixed_credentials(:post, RFC5849::PHOTOS_URL, {"id" => "1"})

      assert_includes header.send(:normalized_params), "id=1"
    end
  end
end
