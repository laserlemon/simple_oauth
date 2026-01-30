require "test_helper"

module SimpleOAuth
  class HeaderValidationTest < Minitest::Test
    include TestHelpers

    cover "SimpleOAuth::Header*"

    # #valid? tests - HMAC-SHA1

    def test_valid_hmac_sha1_is_not_valid_without_secrets
      secrets = {consumer_secret: "CONSUMER_SECRET", token_secret: "TOKEN_SECRET"}
      header = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friends/list.json", {}, secrets)
      parsed_header = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friends/list.json", {}, header)

      refute_predicate parsed_header, :valid?
    end

    def test_valid_hmac_sha1_is_valid_with_secrets
      secrets = {consumer_secret: "CONSUMER_SECRET", token_secret: "TOKEN_SECRET"}
      header = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friends/list.json", {}, secrets)
      parsed_header = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friends/list.json", {}, header)

      assert parsed_header.valid?(secrets)
    end

    # #valid? tests - RSA-SHA1

    def test_valid_rsa_sha1_raises_type_error_without_private_key
      secrets = {consumer_secret: rsa_private_key}
      header = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friends/list.json", {},
        secrets.merge(signature_method: "RSA-SHA1"))
      parsed_header = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friends/list.json", {}, header)
      assert_raises(TypeError) { parsed_header.valid? }
    end

    def test_valid_rsa_sha1_is_valid_with_private_key
      secrets = {consumer_secret: rsa_private_key}
      header = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friends/list.json", {},
        secrets.merge(signature_method: "RSA-SHA1"))
      parsed_header = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friends/list.json", {}, header)

      assert parsed_header.valid?(secrets)
    end

    # #valid? tests - PLAINTEXT

    def test_valid_plaintext_is_not_valid_without_secrets
      secrets = {consumer_secret: "CONSUMER_SECRET", token_secret: "TOKEN_SECRET"}
      header = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friends/list.json", {},
        secrets.merge(signature_method: "PLAINTEXT"))
      parsed_header = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friends/list.json", {}, header)

      refute_predicate parsed_header, :valid?
    end

    def test_valid_plaintext_is_valid_with_secrets
      secrets = {consumer_secret: "CONSUMER_SECRET", token_secret: "TOKEN_SECRET"}
      header = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friends/list.json", {},
        secrets.merge(signature_method: "PLAINTEXT"))
      parsed_header = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friends/list.json", {}, header)

      assert parsed_header.valid?(secrets)
    end

    def test_valid_restores_original_options_after_validation
      secrets = {consumer_secret: "CONSUMER_SECRET", token_secret: "TOKEN_SECRET"}
      header = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friends/list.json", {}, secrets)
      parsed_header = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friends/list.json", {}, header)
      original_options = parsed_header.options.dup

      parsed_header.valid?(secrets)

      assert_equal original_options, parsed_header.options
    end

    def test_valid_returns_false_when_signature_does_not_match
      secrets = {consumer_secret: "CONSUMER_SECRET", token_secret: "TOKEN_SECRET"}
      header = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friends/list.json", {}, secrets)
      parsed_header = SimpleOAuth::Header.new(:get, "https://api.x.com/1.1/friends/list.json", {}, header)

      refute parsed_header.valid?(consumer_secret: "WRONG_SECRET", token_secret: "WRONG_TOKEN")
    end
  end
end
