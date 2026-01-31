require "test_helper"

module SimpleOAuth
  # Tests for realm parameter handling per RFC 5849.
  #
  # Examples use values from RFC 5849 Section 1.2 and Section 3.5.1:
  # - realm="Photos" with consumer_key="dpf43f3p2l4k3l03"
  # - realm="Example" with consumer_key="0685bd9184jfhq22"
  class HeaderRealmTest < Minitest::Test
    include TestHelpers

    cover "SimpleOAuth::Header*"

    def test_realm_is_included_in_header
      # RFC 5849 Section 3.5.1 example: realm="Example"
      header = SimpleOAuth::Header.new(:get, "http://example.com/request", {},
        RFC5849::HeaderExample::OPTIONS.merge(realm: "Example"))

      assert_includes header.to_s, 'realm="Example"'
    end

    def test_realm_is_included_in_signed_attributes
      # RFC 5849 Section 1.2 example: realm="Photos"
      header = SimpleOAuth::Header.new(:get, "https://photos.example.net/initiate", {},
        RFC5849::PHOTOS_OPTIONS.merge(realm: "Photos"))

      assert_equal "Photos", header.signed_attributes[:realm]
    end

    def test_realm_is_excluded_from_signature_computation
      # Per RFC 5849 Section 3.4.1.3.1, realm MUST be excluded from signature base string.
      # Using both RFC examples: "Photos" (Section 1.2) and "Example" (Section 3.5.1)
      header_photos = SimpleOAuth::Header.new(:get, "http://example.com/request", {},
        RFC5849::HeaderExample::OPTIONS.merge(realm: "Photos"))
      header_example = SimpleOAuth::Header.new(:get, "http://example.com/request", {},
        RFC5849::HeaderExample::OPTIONS.merge(realm: "Example"))
      header_no_realm = SimpleOAuth::Header.new(:get, "http://example.com/request", {},
        RFC5849::HeaderExample::OPTIONS)

      # Different realm values MUST produce identical signatures
      photos_sig = header_photos.signed_attributes[:oauth_signature]

      assert_equal photos_sig, header_example.signed_attributes[:oauth_signature]
      assert_equal photos_sig, header_no_realm.signed_attributes[:oauth_signature]
    end

    def test_no_realm_by_default
      header = SimpleOAuth::Header.new(:get, "http://example.com/request", {},
        RFC5849::HeaderExample::OPTIONS)

      refute_includes header.to_s, "realm"
    end

    def test_realm_does_not_raise_extra_keys_error
      header = SimpleOAuth::Header.new(:get, "http://example.com/request", {},
        RFC5849::HeaderExample::OPTIONS.merge(realm: "Example"))

      assert header.to_s
    end

    def test_realm_value_is_escaped
      # RFC 5849 Section 3.5.1: realm values are percent-encoded per RFC 3986
      header = SimpleOAuth::Header.new(:get, "http://example.com/request", {},
        RFC5849::HeaderExample::OPTIONS.merge(realm: "Example Realm"))

      assert_includes header.to_s, 'realm="Example%20Realm"'
    end

    def test_realm_nil_is_not_included
      header = SimpleOAuth::Header.new(:get, "http://example.com/request", {},
        RFC5849::HeaderExample::OPTIONS.merge(realm: nil))

      refute_includes header.to_s, "realm"
    end
  end
end
