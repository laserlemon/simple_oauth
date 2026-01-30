require "test_helper"

module SimpleOAuth
  class HeaderUrlTest < Minitest::Test
    cover "SimpleOAuth::Header*"

    def test_initialize_accepts_uri_object
      uri = URI.parse("https://api.twitter.com/1/statuses/friends.json")
      header = SimpleOAuth::Header.new(:get, uri, {})

      assert_equal "https://api.twitter.com/1/statuses/friends.json", header.url
    end

    def test_initialize_normalizes_scheme_to_lowercase
      header = SimpleOAuth::Header.new(:get, "HTTPS://example.com/path", {})

      assert header.url.start_with?("https://")
    end

    def test_url_removes_query_string
      header = SimpleOAuth::Header.new(:get, "https://api.twitter.com/path?query=value", {})

      refute_includes header.url, "?"
      refute_includes header.url, "query"
    end

    def test_url_removes_fragment
      header = SimpleOAuth::Header.new(:get, "https://api.twitter.com/path#fragment", {})

      refute_includes header.url, "#"
      refute_includes header.url, "fragment"
    end

    def test_url_can_be_called_multiple_times_consistently
      header = SimpleOAuth::Header.new(:get, "https://api.twitter.com/path?query=value", {})
      first_result = header.url
      second_result = header.url

      assert_equal first_result, second_result
    end

    def test_url_preserves_internal_uri_with_query
      header = SimpleOAuth::Header.new(:get, "https://api.twitter.com/path?query=value", {})
      header.url
      url_params = header.send(:url_params)

      assert_equal [%w[query value]], url_params
    end
  end
end
