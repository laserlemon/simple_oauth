require "test_helper"

module SimpleOAuth
  class HeaderSignatureFormatTest < Minitest::Test
    include TestHelpers

    cover "SimpleOAuth::Header*"

    def test_hmac_sha1_signature_contains_no_newlines
      header = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friends/list.json", {}, twitter_options)
      signature = header.send(:hmac_sha1_signature)

      refute_includes signature, "\n"
    end

    def test_rsa_sha1_signature_contains_no_newlines
      header = SimpleOAuth::Header.new(:get, "http://photos.example.net/photos", {file: "vacaction.jpg", size: "original"},
        rsa_sha1_options)
      signature = header.send(:rsa_sha1_signature)

      refute_includes signature, "\n"
    end

    def test_hmac_sha1_signature_is_base64_encoded
      header = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friends/list.json", {}, twitter_options)
      signature = header.send(:hmac_sha1_signature)

      assert_match %r{\A[A-Za-z0-9+/]+=*\z}, signature
    end

    def test_rsa_sha1_signature_is_base64_encoded
      header = SimpleOAuth::Header.new(:get, "http://photos.example.net/photos", {file: "vacaction.jpg", size: "original"},
        rsa_sha1_options)
      signature = header.send(:rsa_sha1_signature)

      assert_match %r{\A[A-Za-z0-9+/]+=*\z}, signature
    end

    private

    def twitter_options
      {
        consumer_key: "key",
        consumer_secret: "secret",
        nonce: "nonce123",
        signature_method: "HMAC-SHA1",
        timestamp: "1234567890",
        token: "token",
        token_secret: "token_secret"
      }
    end

    def rsa_sha1_options
      {
        consumer_key: "dpf43f3p2l4k3l03",
        consumer_secret: rsa_private_key,
        nonce: "13917289812797014437",
        signature_method: "RSA-SHA1",
        timestamp: "1196666512"
      }
    end
  end
end
