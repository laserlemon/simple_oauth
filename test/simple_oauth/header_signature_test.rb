require "test_helper"

module SimpleOAuth
  class HeaderSignatureTest < Minitest::Test
    include TestHelpers

    cover "SimpleOAuth::Header*"

    # #signature tests - dispatches to correct Signature method

    def test_signature_uses_hmac_sha1_for_hmac_sha1_method
      header = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friends/list.json", {},
        consumer_key: "key", consumer_secret: "secret", signature_method: "HMAC-SHA1",
        nonce: "nonce", timestamp: "12345")

      # Verify signature is computed (non-empty string)
      assert_kind_of String, header.send(:signature)
      refute_empty header.send(:signature)
    end

    def test_signature_uses_hmac_sha256_for_hmac_sha256_method
      header = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friends/list.json", {},
        consumer_key: "key", consumer_secret: "secret", signature_method: "HMAC-SHA256",
        nonce: "nonce", timestamp: "12345")

      assert_kind_of String, header.send(:signature)
      refute_empty header.send(:signature)
    end

    def test_signature_uses_rsa_sha1_for_rsa_sha1_method
      header = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friends/list.json", {},
        consumer_key: "key", consumer_secret: rsa_private_key, signature_method: "RSA-SHA1",
        nonce: "nonce", timestamp: "12345")

      assert_kind_of String, header.send(:signature)
      refute_empty header.send(:signature)
    end

    def test_signature_uses_plaintext_for_plaintext_method
      header = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friends/list.json", {},
        consumer_key: "key", consumer_secret: "secret", token_secret: "token_secret",
        signature_method: "PLAINTEXT", nonce: "nonce", timestamp: "12345")

      # PLAINTEXT signature is just the escaped secrets joined with &
      assert_equal "secret&token_secret", header.send(:signature)
    end

    def test_signature_method_converts_dashes_to_underscores
      header1 = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friends/list.json", {},
        consumer_key: "key", consumer_secret: "secret", signature_method: "HMAC-SHA1",
        nonce: "nonce", timestamp: "12345")
      header2 = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friends/list.json", {},
        consumer_key: "key", consumer_secret: "secret", signature_method: "HMAC-SHA256",
        nonce: "nonce", timestamp: "12345")

      # Different signature methods produce different signatures
      refute_equal header1.send(:signature), header2.send(:signature)
    end

    def test_signature_method_dispatches_correctly_regardless_of_case
      # Both uppercase and lowercase signature methods should work
      header_upper = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friends/list.json", {},
        consumer_key: "key", consumer_secret: "secret", signature_method: "HMAC-SHA1",
        nonce: "nonce", timestamp: "12345")
      header_lower = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friends/list.json", {},
        consumer_key: "key", consumer_secret: "secret", signature_method: "hmac-sha1",
        nonce: "nonce", timestamp: "12345")

      # Both should produce valid signatures (non-empty base64 strings)
      assert_match %r{\A[A-Za-z0-9+/]+=*\z}, header_upper.send(:signature)
      assert_match %r{\A[A-Za-z0-9+/]+=*\z}, header_lower.send(:signature)
    end

    def test_same_inputs_produce_same_signature
      options = {consumer_key: "key", consumer_secret: "secret", signature_method: "HMAC-SHA1",
                 nonce: "nonce", timestamp: "12345"}
      header1 = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friends/list.json", {}, options)
      header2 = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friends/list.json", {}, options)

      assert_equal header1.send(:signature), header2.send(:signature)
    end

    def test_different_secrets_produce_different_signatures
      header1 = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friends/list.json", {},
        consumer_key: "key", consumer_secret: "secret1", signature_method: "HMAC-SHA1",
        nonce: "nonce", timestamp: "12345")
      header2 = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friends/list.json", {},
        consumer_key: "key", consumer_secret: "secret2", signature_method: "HMAC-SHA1",
        nonce: "nonce", timestamp: "12345")

      refute_equal header1.send(:signature), header2.send(:signature)
    end

    def test_rsa_sha1_uses_raw_consumer_secret_not_escaped_secret
      # RSA-SHA1 needs the raw PEM key, not the escaped secret string
      # This test ensures the signature method comparison works correctly
      header = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friends/list.json", {},
        consumer_key: "key", consumer_secret: rsa_private_key, token_secret: "ignored",
        signature_method: "RSA-SHA1", nonce: "nonce", timestamp: "12345")

      # If the secret was escaped (like for HMAC), this would fail because
      # the PEM key would be mangled
      signature = header.send(:signature)

      assert_match %r{\A[A-Za-z0-9+/]+=*\z}, signature
    end
  end
end
