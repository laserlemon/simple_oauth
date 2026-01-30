require "test_helper"

module SimpleOAuth
  class HeaderClassMethodsTest < Minitest::Test
    cover "SimpleOAuth::Header*"

    # .default_options tests

    def test_default_options_is_different_every_time
      first = SimpleOAuth::Header.default_options
      second = SimpleOAuth::Header.default_options

      refute_equal first, second
    end

    def test_default_options_is_used_for_new_headers
      header = SimpleOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friendships.json", {})

      assert_includes header.options.keys, :nonce
      assert_includes header.options.keys, :signature_method
      assert_includes header.options.keys, :timestamp
    end

    def test_default_options_includes_version_key
      header = SimpleOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friendships.json", {})

      assert_includes header.options.keys, :version
    end

    def test_default_options_includes_signature_method
      refute_nil SimpleOAuth::Header.default_options[:signature_method]
    end

    def test_default_options_includes_oauth_version
      refute_nil SimpleOAuth::Header.default_options[:version]
    end

    def test_default_options_nonce_is_32_hex_characters
      nonce = SimpleOAuth::Header.default_options[:nonce]

      assert_match(/\A[0-9a-f]{32}\z/, nonce)
    end

    def test_default_options_timestamp_is_integer_string
      timestamp = SimpleOAuth::Header.default_options[:timestamp]

      assert_match(/\A\d+\z/, timestamp)
      assert_equal Time.now.to_i.to_s.length, timestamp.length
    end
  end
end
