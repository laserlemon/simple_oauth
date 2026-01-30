require "test_helper"

module SimpleOAuth
  class HeaderParamsTest < Minitest::Test
    cover "SimpleOAuth::Header*"

    # #normalized_params tests

    def test_normalized_params_returns_a_string
      header = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friendships/show.json", {})
      header.define_singleton_method(:signature_params) { [%w[A 4], %w[B 3], %w[B 2], %w[C 1], ["D[]", "0 "]] }

      assert_kind_of String, header.send(:normalized_params)
    end

    def test_normalized_params_joins_pairs_with_ampersands
      header = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friendships/show.json", {})
      signature_params = [%w[A 4], %w[B 3], %w[B 2], %w[C 1], ["D[]", "0 "]]
      header.define_singleton_method(:signature_params) { signature_params }
      parts = header.send(:normalized_params).split("&")

      assert_equal signature_params.size, parts.size
    end

    def test_normalized_params_joins_key_value_with_equal_signs
      header = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friendships/show.json", {})
      header.define_singleton_method(:signature_params) { [%w[A 4], %w[B 3], %w[B 2], %w[C 1], ["D[]", "0 "]] }
      pairs = header.send(:normalized_params).split("&").collect { |p| p.split("=") }

      assert(pairs.all? { |p| p.size == 2 })
    end

    # #signature_params tests

    def test_signature_params_combines_attributes_params_and_url_params
      header = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friendships/show.json", {})
      header.define_singleton_method(:attributes) { {attribute: "ATTRIBUTE"} }
      header.define_singleton_method(:params) { {"param" => "PARAM"} }
      header.define_singleton_method(:url_params) { [%w[url_param 1], %w[url_param 2]] }
      expected = [[:attribute, "ATTRIBUTE"], %w[param PARAM], %w[url_param 1], %w[url_param 2]]

      assert_equal expected, header.send(:signature_params)
    end

    # #url_params tests

    def test_url_params_returns_empty_array_when_no_query_parameters
      header = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friendships/show.json", {})

      assert_empty header.send(:url_params)
    end

    def test_url_params_returns_key_value_pairs_for_query_parameters
      header = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friendships/show.json?test=TEST", {})

      assert_equal [%w[test TEST]], header.send(:url_params)
    end

    def test_url_params_sorts_values_for_repeated_keys
      header = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friendships/show.json?test=3&test=1&test=2", {})

      assert_equal [%w[test 1], %w[test 2], %w[test 3]], header.send(:url_params)
    end

    def test_url_params_handles_empty_query_string
      header = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friendships/show.json?", {})

      assert_empty header.send(:url_params)
    end

    def test_normalized_params_sorts_params_alphabetically
      header = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friendships/show.json", {})
      header.define_singleton_method(:signature_params) { [%w[z last], %w[a first], %w[m middle]] }
      result = header.send(:normalized_params)

      assert_equal "a=first&m=middle&z=last", result
    end

    def test_url_params_accumulates_multiple_keys
      header = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friendships/show.json?foo=1&bar=2&baz=3", {})
      url_params = header.send(:url_params)
      expected = [%w[bar 2], %w[baz 3], %w[foo 1]]

      assert_equal expected, url_params.sort
    end
  end
end
