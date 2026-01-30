require "test_helper"

module SimpleOAuth
  class HeaderAttributesTest < Minitest::Test
    cover "SimpleOAuth::Header*"

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

    def test_attributes_does_not_raise_when_ignore_extra_keys_is_true
      header = build_header_with_all_attribute_keys
      header.options[:ignore_extra_keys] = true

      assert header.send(:attributes)
    end

    def test_attributes_does_not_raise_when_no_extra_keys
      header = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friendships/show.json", {},
        consumer_key: "key")

      assert header.send(:attributes)
    end

    def test_attributes_raises_when_ignore_extra_keys_is_explicitly_false
      header = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friendships/show.json", {},
        other: "OTHER")
      header.options[:ignore_extra_keys] = false

      assert_raises(RuntimeError) { header.send(:attributes) }
    end

    def test_attributes_error_message_includes_comma_separator_for_multiple_extra_keys
      header = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friendships/show.json", {},
        extra1: "EXTRA1", extra2: "EXTRA2")

      error = assert_raises(RuntimeError) { header.send(:attributes) }
      assert_includes error.message, ", "
    end

    private

    def build_header_with_all_attribute_keys
      options = {}
      SimpleOAuth::Header::ATTRIBUTE_KEYS.each { |k| options[k] = k.to_s.upcase }
      options[:other] = "OTHER"
      SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friendships/show.json", {}, options)
    end
  end
end
