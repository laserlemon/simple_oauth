require "test_helper"

module SimpleOAuth
  class HeaderRealmTest < Minitest::Test
    cover "SimpleOAuth::Header*"

    def test_realm_is_included_in_header
      header = SimpleOAuth::Header.new(:get, "https://api.example.com/resource", {},
        consumer_key: "key",
        consumer_secret: "secret",
        realm: "Example")

      assert_includes header.to_s, 'realm="Example"'
    end

    def test_realm_is_included_in_signed_attributes
      header = SimpleOAuth::Header.new(:get, "https://api.example.com/resource", {},
        consumer_key: "key",
        consumer_secret: "secret",
        realm: "Example")

      assert_equal "Example", header.signed_attributes[:realm]
    end

    def test_realm_is_included_in_signature_computation
      options = {consumer_key: "key", consumer_secret: "secret", nonce: "fixed", timestamp: "1234567890"}
      header1 = SimpleOAuth::Header.new(:get, "https://api.example.com/resource", {}, options.merge(realm: "Example1"))
      header2 = SimpleOAuth::Header.new(:get, "https://api.example.com/resource", {}, options.merge(realm: "Example2"))

      refute_equal header1.signed_attributes[:oauth_signature], header2.signed_attributes[:oauth_signature]
    end

    def test_no_realm_by_default
      header = SimpleOAuth::Header.new(:get, "https://api.example.com/resource", {},
        consumer_key: "key",
        consumer_secret: "secret")

      refute_includes header.to_s, "realm"
    end

    def test_realm_does_not_raise_extra_keys_error
      header = SimpleOAuth::Header.new(:get, "https://api.example.com/resource", {},
        consumer_key: "key",
        consumer_secret: "secret",
        realm: "Example")

      assert header.to_s
    end

    def test_realm_value_is_escaped
      header = SimpleOAuth::Header.new(:get, "https://api.example.com/resource", {},
        consumer_key: "key",
        consumer_secret: "secret",
        realm: "Example Realm")

      assert_includes header.to_s, 'realm="Example%20Realm"'
    end

    def test_realm_nil_is_not_included
      header = SimpleOAuth::Header.new(:get, "https://api.example.com/resource", {},
        consumer_key: "key",
        consumer_secret: "secret",
        realm: nil)

      refute_includes header.to_s, "realm"
    end
  end
end
