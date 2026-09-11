require "test_helper"

module SimpleOAuth
  # Tests that oauth_body_hash uses the hash algorithm of the signature method
  class HeaderBodyHashDigestTest < Minitest::Test
    include TestHelpers

    cover "SimpleOAuth::Header*"
    cover "SimpleOAuth::Signature*"

    BODY = '{"status":"testing"}'.freeze

    def teardown
      Signature.reset!
    end

    def test_sha1_methods_hash_the_body_with_sha1
      assert_equal digest_of(BODY, "SHA1"), body_hash_for("HMAC-SHA1")
    end

    def test_sha256_methods_hash_the_body_with_sha256
      assert_equal digest_of(BODY, "SHA256"), body_hash_for("HMAC-SHA256")
    end

    def test_rsa_methods_hash_the_body_with_their_own_digest
      assert_equal digest_of(BODY, "SHA256"), body_hash_for("RSA-SHA256", consumer_secret: rsa_private_key)
    end

    def test_a_custom_method_hashes_the_body_with_its_registered_digest
      Signature.register("HMAC-SHA512", digest: "SHA512") { |secret, base| "#{secret}#{base}" }

      assert_equal digest_of(BODY, "SHA512"), body_hash_for("HMAC-SHA512")
    end

    def test_a_custom_method_without_a_digest_hashes_the_body_with_sha1
      Signature.register("HMAC-SHA512") { |secret, base| "#{secret}#{base}" }

      assert_equal digest_of(BODY, "SHA1"), body_hash_for("HMAC-SHA512")
    end

    def test_an_explicit_body_hash_is_kept
      header = build_header(:post, RFC5849::PHOTOS_URL, {}, signature_method: "HMAC-SHA256", body_hash: "given")

      assert_equal "given", header.signed_attributes[:oauth_body_hash]
    end

    def test_digest_of_an_unknown_signature_method
      assert_raises(ArgumentError) { Signature.digest("HMAC-SHA512") }
    end

    private

    def digest_of(body, algorithm)
      Base64.strict_encode64(OpenSSL::Digest.digest(algorithm, body))
    end

    def body_hash_for(signature_method, **options)
      defaults = {consumer_key: RFC5849::CONSUMER_KEY, consumer_secret: RFC5849::CONSUMER_SECRET}
      header = SimpleOAuth::Header.new(:post, RFC5849::PHOTOS_URL, {},
        defaults.merge(options).merge(signature_method: signature_method), BODY)
      header.signed_attributes[:oauth_body_hash]
    end
  end
end
