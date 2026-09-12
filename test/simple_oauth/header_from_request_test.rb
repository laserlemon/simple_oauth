require "net/http"
require "test_helper"

module SimpleOAuth
  # Tests for building a header straight from an HTTP request
  class HeaderFromRequestTest < Minitest::Test
    include TestHelpers

    cover "SimpleOAuth::Header*"

    OPTIONS = {consumer_key: RFC5849::CONSUMER_KEY, consumer_secret: RFC5849::CONSUMER_SECRET,
               nonce: "chapoH", timestamp: "137131202"}.freeze

    def test_signs_query_parameters
      request = Net::HTTP::Get.new(URI("#{RFC5849::PHOTOS_URL}?file=vacation.jpg&size=original"))
      expected = SimpleOAuth::Header.new(:get, "#{RFC5849::PHOTOS_URL}?file=vacation.jpg&size=original", {}, OPTIONS)

      assert_equal expected.to_s, SimpleOAuth::Header.from_request(request, OPTIONS).to_s
    end

    def test_signs_a_form_encoded_body
      request = Net::HTTP::Post.new(URI(RFC5849::PHOTOS_URL))
      request.set_form_data("status" => "Hello Ladies + Gentlemen")
      expected = SimpleOAuth::Header.new(:post, RFC5849::PHOTOS_URL, {"status" => "Hello Ladies + Gentlemen"}, OPTIONS)

      assert_equal expected.to_s, SimpleOAuth::Header.from_request(request, OPTIONS).to_s
    end

    def test_signs_a_repeated_form_parameter
      request = Net::HTTP::Post.new(URI(RFC5849::PHOTOS_URL))
      request.body = "ids=1&ids=2"
      request["Content-Type"] = "application/x-www-form-urlencoded"
      expected = SimpleOAuth::Header.new(:post, RFC5849::PHOTOS_URL, [%w[ids 1], %w[ids 2]], OPTIONS)

      assert_equal expected.to_s, SimpleOAuth::Header.from_request(request, OPTIONS).to_s
    end

    def test_accepts_a_content_type_with_parameters
      request = Net::HTTP::Post.new(URI(RFC5849::PHOTOS_URL))
      request.body = "status=Hello"
      request["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-8"
      expected = SimpleOAuth::Header.new(:post, RFC5849::PHOTOS_URL, {"status" => "Hello"}, OPTIONS)

      assert_equal expected.to_s, SimpleOAuth::Header.from_request(request, OPTIONS).to_s
    end

    def test_accepts_a_content_type_in_uppercase
      request = Net::HTTP::Post.new(URI(RFC5849::PHOTOS_URL))
      request.body = "status=Hello"
      request["Content-Type"] = "Application/X-WWW-Form-UrlEncoded"
      expected = SimpleOAuth::Header.new(:post, RFC5849::PHOTOS_URL, {"status" => "Hello"}, OPTIONS)

      assert_equal expected.to_s, SimpleOAuth::Header.from_request(request, OPTIONS).to_s
    end

    def test_accepts_a_content_type_padded_with_spaces
      request = Net::HTTP::Post.new(URI(RFC5849::PHOTOS_URL))
      request.body = "status=Hello"
      request["Content-Type"] = " application/x-www-form-urlencoded ; charset=utf-8"
      expected = SimpleOAuth::Header.new(:post, RFC5849::PHOTOS_URL, {"status" => "Hello"}, OPTIONS)

      assert_equal expected.to_s, SimpleOAuth::Header.from_request(request, OPTIONS).to_s
    end

    def test_hashes_a_body_whose_media_type_only_begins_with_the_form_media_type
      request = Net::HTTP::Post.new(URI(RFC5849::PHOTOS_URL))
      request.body = '{"status":"Hello"}'
      request["Content-Type"] = "application/x-www-form-urlencoded-json"
      header = SimpleOAuth::Header.from_request(request, OPTIONS)

      assert_equal SimpleOAuth::Header.body_hash('{"status":"Hello"}'), header.signed_attributes[:oauth_body_hash]
      assert_empty header.params
    end

    def test_hashes_a_body_that_is_not_form_encoded
      request = Net::HTTP::Post.new(URI(RFC5849::PHOTOS_URL), "Content-Type" => "application/json")
      request.body = '{"status":"Hello"}'
      header = SimpleOAuth::Header.from_request(request, OPTIONS)

      assert_equal SimpleOAuth::Header.body_hash('{"status":"Hello"}'), header.signed_attributes[:oauth_body_hash]
    end

    def test_signs_no_parameters_for_a_body_that_is_not_form_encoded
      request = Net::HTTP::Post.new(URI(RFC5849::PHOTOS_URL), "Content-Type" => "application/json")
      request.body = '{"status":"Hello"}'

      assert_empty SimpleOAuth::Header.from_request(request, OPTIONS).params
    end

    def test_a_request_without_a_body
      request = Net::HTTP::Get.new(URI(RFC5849::PHOTOS_URL))
      header = SimpleOAuth::Header.from_request(request, OPTIONS)

      assert_equal SimpleOAuth::Header.new(:get, RFC5849::PHOTOS_URL, {}, OPTIONS).to_s, header.to_s
      refute_includes header.to_s, "oauth_body_hash"
    end

    def test_parses_an_existing_authorization_header_for_verification
      signed = SimpleOAuth::Header.new(:get, RFC5849::PHOTOS_URL, {}, OPTIONS)
      request = Net::HTTP::Get.new(URI(RFC5849::PHOTOS_URL))

      assert SimpleOAuth::Header.from_request(request, signed.to_s).valid?(consumer_secret: RFC5849::CONSUMER_SECRET)
    end

    def test_a_form_encoded_request_without_a_body
      request = Net::HTTP::Post.new(URI(RFC5849::PHOTOS_URL))
      request["Content-Type"] = "application/x-www-form-urlencoded"

      assert_empty SimpleOAuth::Header.from_request(request, OPTIONS).params
    end

    def test_signing_without_oauth_options
      request = Net::HTTP::Get.new(URI(RFC5849::PHOTOS_URL))

      refute_includes SimpleOAuth::Header.from_request(request).to_s, "oauth_consumer_key"
    end

    def test_a_request_without_a_uri
      error = assert_raises(ArgumentError) { SimpleOAuth::Header.from_request(Net::HTTP::Get.new("/photos"), OPTIONS) }

      assert_equal "The request has no URI", error.message
    end
  end
end
