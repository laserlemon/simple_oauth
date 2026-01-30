require "test_helper"

module SimpleOAuth
  # rubocop:disable Metrics/ClassLength
  class SignatureRegistryTest < Minitest::Test
    include TestHelpers

    cover "SimpleOAuth::Signature*"

    def teardown
      # Reset registry after each test to avoid test pollution
      Signature.reset!
    end

    # .register tests

    def test_register_adds_custom_signature_method
      Signature.register("CUSTOM-METHOD") { |secret, base| "custom:#{secret}:#{base}" }

      assert Signature.registered?("CUSTOM-METHOD")
    end

    def test_register_normalizes_method_name
      Signature.register("My-Custom-Method") { |_s, _b| "sig" }

      assert Signature.registered?("my_custom_method")
      assert Signature.registered?("MY-CUSTOM-METHOD")
    end

    def test_register_accepts_symbol_name
      Signature.register(:custom_symbol_method) { |_s, _b| "sig" }

      assert Signature.registered?("custom_symbol_method")
      assert Signature.registered?(:custom_symbol_method)
    end

    def test_register_with_rsa_flag
      Signature.register("RSA-CUSTOM", rsa: true) { |_key, base| "rsa:#{base}" }

      assert Signature.rsa?("RSA-CUSTOM")
    end

    def test_register_without_rsa_flag_defaults_to_false
      Signature.register("NON-RSA") { |_s, _b| "sig" }

      refute Signature.rsa?("NON-RSA")
    end

    # .registered? tests

    # rubocop:disable Minitest/MultipleAssertions
    def test_registered_returns_true_for_builtin_methods
      assert Signature.registered?("HMAC-SHA1")
      assert Signature.registered?("HMAC-SHA256")
      assert Signature.registered?("RSA-SHA1")
      assert Signature.registered?("PLAINTEXT")
    end
    # rubocop:enable Minitest/MultipleAssertions

    def test_registered_returns_false_for_unknown_methods
      refute Signature.registered?("UNKNOWN-METHOD")
    end

    def test_registered_is_case_insensitive
      assert Signature.registered?("hmac-sha1")
      assert Signature.registered?("Hmac-Sha1")
      assert Signature.registered?("HMAC-SHA1")
    end

    # .methods tests

    def test_methods_returns_array_of_strings
      methods = Signature.methods

      assert_kind_of Array, methods
      methods.each { |m| assert_kind_of String, m }
    end

    # rubocop:disable Minitest/MultipleAssertions
    def test_methods_returns_registered_method_names
      methods = Signature.methods

      assert_includes methods, "hmac_sha1"
      assert_includes methods, "hmac_sha256"
      assert_includes methods, "rsa_sha1"
      assert_includes methods, "plaintext"
    end
    # rubocop:enable Minitest/MultipleAssertions

    def test_methods_includes_custom_registered_methods
      Signature.register("CUSTOM") { |_s, _b| "sig" }

      assert_includes Signature.methods, "custom"
    end

    # .rsa? tests

    def test_rsa_returns_true_for_rsa_sha1
      # rubocop:disable Minitest/AssertTruthy
      assert_equal true, Signature.rsa?("RSA-SHA1")
      # rubocop:enable Minitest/AssertTruthy
    end

    def test_rsa_returns_false_for_hmac_methods
      refute Signature.rsa?("HMAC-SHA1")
      refute Signature.rsa?("HMAC-SHA256")
    end

    def test_rsa_returns_false_for_plaintext
      refute Signature.rsa?("PLAINTEXT")
    end

    def test_rsa_returns_false_for_unknown_method
      refute Signature.rsa?("UNKNOWN")
    end

    def test_rsa_returns_boolean_false_not_nil
      # Verify we get actual false, not nil (for proper boolean semantics)
      # rubocop:disable Minitest/RefuteFalse
      assert_equal false, Signature.rsa?("HMAC-SHA1")
      assert_equal false, Signature.rsa?("UNKNOWN")
      # rubocop:enable Minitest/RefuteFalse
    end

    # .sign tests

    def test_sign_computes_hmac_sha1_signature
      signature = Signature.sign("HMAC-SHA1", "secret", "base")

      # Verify the exact expected HMAC-SHA1 signature
      expected = Base64.encode64(OpenSSL::HMAC.digest("SHA1", "secret", "base")).delete("\n")

      assert_equal expected, signature
    end

    def test_sign_computes_hmac_sha256_signature
      signature = Signature.sign("HMAC-SHA256", "secret", "base")

      # Verify the exact expected HMAC-SHA256 signature
      expected = Base64.encode64(OpenSSL::HMAC.digest("SHA256", "secret", "base")).delete("\n")

      assert_equal expected, signature
    end

    def test_sign_computes_rsa_sha1_signature
      signature = Signature.sign("RSA-SHA1", rsa_private_key, "base")

      # Verify the exact expected RSA-SHA1 signature
      private_key = OpenSSL::PKey::RSA.new(rsa_private_key)
      expected = Base64.encode64(private_key.sign("SHA1", "base")).delete("\n")

      assert_equal expected, signature
    end

    def test_sign_computes_plaintext_signature
      signature = Signature.sign("PLAINTEXT", "secret&token", "base")

      assert_equal "secret&token", signature
    end

    def test_sign_uses_custom_registered_method
      Signature.register("CUSTOM") { |secret, base| "custom:#{secret}:#{base}" }

      signature = Signature.sign("CUSTOM", "mysecret", "mybase")

      assert_equal "custom:mysecret:mybase", signature
    end

    # rubocop:disable Minitest/MultipleAssertions
    def test_sign_raises_for_unknown_method
      error = assert_raises(ArgumentError) do
        Signature.sign("UNKNOWN-METHOD", "secret", "base")
      end

      assert_includes error.message, "Unknown signature method: UNKNOWN-METHOD"
      assert_includes error.message, "Registered methods:"
      # Verify comma-separated list format
      assert_includes error.message, "hmac_sha1, "
    end
    # rubocop:enable Minitest/MultipleAssertions

    def test_sign_is_case_insensitive
      sig1 = Signature.sign("HMAC-SHA1", "secret", "base")
      sig2 = Signature.sign("hmac-sha1", "secret", "base")
      sig3 = Signature.sign("Hmac-Sha1", "secret", "base")

      assert_equal sig1, sig2
      assert_equal sig2, sig3
    end

    def test_sign_normalizes_dashes_to_underscores
      sig1 = Signature.sign("HMAC-SHA1", "secret", "base")
      sig2 = Signature.sign("HMAC_SHA1", "secret", "base")

      assert_equal sig1, sig2
    end

    def test_sign_accepts_symbol_method_name
      sig1 = Signature.sign("HMAC-SHA1", "secret", "base")
      sig2 = Signature.sign(:hmac_sha1, "secret", "base")

      assert_equal sig1, sig2
    end

    # .unregister tests

    def test_unregister_removes_method
      Signature.register("TEMP") { |_s, _b| "sig" }

      assert Signature.registered?("TEMP")

      Signature.unregister("TEMP")

      refute Signature.registered?("TEMP")
    end

    def test_unregister_normalizes_name
      Signature.register("TEMP-METHOD") { |_s, _b| "sig" }

      Signature.unregister("temp_method")

      refute Signature.registered?("TEMP-METHOD")
    end

    # .reset! tests

    def test_reset_restores_builtin_methods
      Signature.unregister("HMAC-SHA1")

      refute Signature.registered?("HMAC-SHA1")

      Signature.reset!

      assert Signature.registered?("HMAC-SHA1")
    end

    def test_reset_removes_custom_methods
      Signature.register("CUSTOM") { |_s, _b| "sig" }

      assert Signature.registered?("CUSTOM")

      Signature.reset!

      refute Signature.registered?("CUSTOM")
    end

    # Integration with Header tests

    def test_header_uses_custom_signature_method
      Signature.register("HMAC-SHA512") do |secret, signature_base|
        Base64.encode64(OpenSSL::HMAC.digest("SHA512", secret, signature_base)).delete("\n")
      end

      header = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friends/list.json", {},
        consumer_key: "key", consumer_secret: "secret", signature_method: "HMAC-SHA512",
        nonce: "nonce", timestamp: "12345")

      # Should produce a valid base64 signature
      assert_match %r{\A[A-Za-z0-9+/]+=*\z}, header.signed_attributes[:oauth_signature]
    end

    def test_header_uses_custom_rsa_method
      Signature.register("RSA-SHA256", rsa: true) do |private_key_pem, signature_base|
        private_key = OpenSSL::PKey::RSA.new(private_key_pem)
        Base64.encode64(private_key.sign("SHA256", signature_base)).delete("\n")
      end

      header = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friends/list.json", {},
        consumer_key: "key", consumer_secret: rsa_private_key, signature_method: "RSA-SHA256",
        nonce: "nonce", timestamp: "12345")

      # Should produce a valid base64 signature
      assert_match %r{\A[A-Za-z0-9+/]+=*\z}, header.signed_attributes[:oauth_signature]
    end

    def test_header_raises_for_unregistered_method
      # rubocop:disable Minitest/AssertRaisesCompoundBody
      assert_raises(ArgumentError) do
        header = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friends/list.json", {},
          consumer_key: "key", consumer_secret: "secret", signature_method: "UNKNOWN",
          nonce: "nonce", timestamp: "12345")
        header.to_s
      end
      # rubocop:enable Minitest/AssertRaisesCompoundBody
    end
  end
  # rubocop:enable Metrics/ClassLength
end
