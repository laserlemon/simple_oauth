require "test_helper"

module SimpleOAuth
  # Tests for oauth_body_hash extension (OAuth Body Hash, draft-eaton-oauth-bodyhash).
  class HeaderBodyHashTest < Minitest::Test
    include TestHelpers

    cover "SimpleOAuth::Header*"

    # .body_hash class method tests

    def test_body_hash_computes_sha1_hash_of_body
      body = '{"text": "Hello, World!"}'
      expected = Base64.encode64(OpenSSL::Digest.digest("SHA1", body)).delete("\n")

      assert_equal expected, SimpleOAuth::Header.body_hash(body)
    end

    def test_body_hash_returns_hash_of_empty_string_for_nil
      expected = Base64.encode64(OpenSSL::Digest.digest("SHA1", "")).delete("\n")

      assert_equal expected, SimpleOAuth::Header.body_hash(nil)
    end

    def test_body_hash_supports_sha256_algorithm
      body = '{"text": "Hello, World!"}'
      expected = Base64.encode64(OpenSSL::Digest.digest("SHA256", body)).delete("\n")

      assert_equal expected, SimpleOAuth::Header.body_hash(body, "SHA256")
    end

    def test_body_hash_contains_no_newlines
      body = "x" * 1000
      hash = SimpleOAuth::Header.body_hash(body)

      refute_includes hash, "\n"
    end

    # .default_options with body tests

    def test_default_options_includes_body_hash_when_body_provided
      options = SimpleOAuth::Header.default_options('{"text": "test"}')

      assert_includes options.keys, :body_hash
    end

    def test_default_options_excludes_body_hash_when_no_body
      options = SimpleOAuth::Header.default_options

      refute_includes options.keys, :body_hash
    end

    def test_default_options_body_hash_matches_body_hash_method
      body = '{"status": "testing oauth_body_hash"}'
      options = SimpleOAuth::Header.default_options(body)
      expected = SimpleOAuth::Header.body_hash(body)

      assert_equal expected, options[:body_hash]
    end

    # Header#initialize with body tests

    def test_initialize_stores_body
      body = '{"text": "Hello"}'
      header = SimpleOAuth::Header.new(:post, "https://photos.example.net/upload", {}, {}, body)

      assert_equal body, header.body
    end

    def test_initialize_without_body_has_nil_body
      header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos", {})

      assert_nil header.body
    end

    def test_initialize_with_body_includes_body_hash_in_options
      body = '{"text": "Hello"}'
      header = SimpleOAuth::Header.new(:post, "https://photos.example.net/upload", {}, {}, body)

      assert_includes header.options.keys, :body_hash
    end

    def test_initialize_without_body_excludes_body_hash_from_options
      header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos", {})

      refute_includes header.options.keys, :body_hash
    end

    # oauth_body_hash in Authorization header tests

    def test_to_s_includes_oauth_body_hash_when_body_provided
      body = '{"text": "Hello"}'
      header = SimpleOAuth::Header.new(:post, "https://photos.example.net/upload", {},
        {consumer_key: RFC5849::CONSUMER_KEY, consumer_secret: RFC5849::CONSUMER_SECRET}, body)

      assert_includes header.to_s, "oauth_body_hash="
    end

    def test_to_s_excludes_oauth_body_hash_when_no_body
      header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos", {},
        consumer_key: RFC5849::CONSUMER_KEY, consumer_secret: RFC5849::CONSUMER_SECRET)

      refute_includes header.to_s, "oauth_body_hash="
    end

    def test_body_hash_is_included_in_signature_computation
      body = '{"text": "Hello"}'
      header1 = SimpleOAuth::Header.new(:post, "https://photos.example.net/upload", {},
        {consumer_key: RFC5849::CONSUMER_KEY, consumer_secret: RFC5849::CONSUMER_SECRET,
         nonce: "chapoH", timestamp: "137131202"}, body)

      different_body = '{"text": "Different"}'
      header2 = SimpleOAuth::Header.new(:post, "https://photos.example.net/upload", {},
        {consumer_key: RFC5849::CONSUMER_KEY, consumer_secret: RFC5849::CONSUMER_SECRET,
         nonce: "chapoH", timestamp: "137131202"}, different_body)

      # Different bodies should produce different signatures
      refute_equal header1.to_s, header2.to_s
    end

    # User can override body_hash in options

    def test_user_provided_body_hash_overrides_computed_hash
      body = '{"text": "Hello"}'
      custom_hash = "custom_hash_value"
      header = SimpleOAuth::Header.new(:post, "https://photos.example.net/upload", {},
        {consumer_key: RFC5849::CONSUMER_KEY, consumer_secret: RFC5849::CONSUMER_SECRET,
         body_hash: custom_hash}, body)

      assert_includes header.to_s, custom_hash
    end
  end
end
