require "test_helper"

module SimpleOAuth
  # Tests that verifying a signature leaves the header's own options alone
  class HeaderVerificationHygieneTest < Minitest::Test
    include TestHelpers

    cover "SimpleOAuth::Header*"
    cover "SimpleOAuth::Signature*"

    CUSTOM_METHOD_HEADER = 'OAuth oauth_consumer_key="key", oauth_nonce="n", oauth_signature="sig", ' \
                           'oauth_signature_method="HMAC-SHA512", oauth_timestamp="1", oauth_version="1.0"'.freeze

    def teardown
      Signature.reset!
    end

    def test_secrets_stay_out_of_the_headers_options
      observed = []
      header = SimpleOAuth::Header.new(:get, RFC5849::PHOTOS_URL, {}, CUSTOM_METHOD_HEADER)
      Signature.register("HMAC-SHA512") do |_secret, _base|
        observed << header.options[:consumer_secret]
        "signature"
      end
      header.valid?(consumer_secret: "s3cret")

      assert_equal [nil], observed
    end

    def test_options_are_unchanged_after_verifying
      header = parsed_header
      before = header.options.dup
      header.valid?(consumer_secret: RFC5849::CONSUMER_SECRET)

      assert_equal before, header.options
    end

    def test_verifying_uses_the_given_secrets
      header = parsed_header

      assert header.valid?(consumer_secret: RFC5849::CONSUMER_SECRET)
      refute header.valid?(consumer_secret: "other")
    end

    def test_verifying_concurrently_gives_each_caller_its_own_answer
      header = parsed_header
      right = Thread.new { Array.new(50) { header.valid?(consumer_secret: RFC5849::CONSUMER_SECRET) } }
      wrong = Thread.new { Array.new(50) { header.valid?(consumer_secret: "other") } }

      assert_equal [true], right.value.uniq
      assert_equal [false], wrong.value.uniq
    end

    private

    def parsed_header(signature_method = "HMAC-SHA1")
      signed = build_header_with_fixed_credentials(:get, RFC5849::PHOTOS_URL, {}, signature_method: signature_method)
      SimpleOAuth::Header.new(:get, RFC5849::PHOTOS_URL, {}, signed.to_s)
    end
  end
end
