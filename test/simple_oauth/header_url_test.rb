require "test_helper"

module SimpleOAuth
  # Tests for URL handling per RFC 5849 Section 3.4.1.2 (Base String URI).
  class HeaderUrlTest < Minitest::Test
    include TestHelpers

    cover "SimpleOAuth::Header*"

    def test_initialize_accepts_uri_object
      # RFC 5849 Section 1.2 - photos.example.net endpoint
      uri = URI.parse("https://photos.example.net/photos")
      header = SimpleOAuth::Header.new(:get, uri, {})

      assert_equal "https://photos.example.net/photos", header.url
    end

    def test_initialize_normalizes_scheme_to_lowercase
      # RFC 5849 Section 3.4.1.2 - scheme is case-insensitive, normalized to lowercase
      header = SimpleOAuth::Header.new(:get, "HTTPS://photos.example.net/photos", {})

      assert header.url.start_with?("https://")
    end

    def test_url_removes_query_string
      # RFC 5849 Section 3.4.1.2 - query component excluded from base string URI
      header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos?file=vacation.jpg", {})

      refute_includes header.url, "?"
      refute_includes header.url, "file"
    end

    def test_url_removes_fragment
      # RFC 5849 Section 3.4.1.2 - fragment excluded from base string URI
      header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos#section", {})

      refute_includes header.url, "#"
      refute_includes header.url, "section"
    end

    def test_url_can_be_called_multiple_times_consistently
      header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos?file=vacation.jpg", {})
      first_result = header.url
      second_result = header.url

      assert_equal first_result, second_result
    end

    def test_url_preserves_internal_uri_with_query
      # Query params should still be available for signature even though url() strips them
      header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos?file=vacation.jpg", {})
      header.url
      url_params = header.send(:url_params)

      assert_equal [%w[file vacation.jpg]], url_params
    end
  end
end
