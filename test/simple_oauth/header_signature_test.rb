require "test_helper"

module SimpleOAuth
  class HeaderSignatureTest < Minitest::Test
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
  end
end
