require "test_helper"

module SimpleOAuth
  class HeaderSignatureIntegrationTest < Minitest::Test
    include TestHelpers

    cover "SimpleOAuth::Header*"

    # #hmac_sha1_signature tests

    def test_hmac_sha1_signature_reproduces_twitter_get
      header = SimpleOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friends.json", {}, twitter_get_options)

      assert_equal twitter_get_expected_header, header.to_s
    end

    def test_hmac_sha1_signature_reproduces_twitter_post
      header = SimpleOAuth::Header.new(:post, "https://api.twitter.com/1/statuses/update.json", {status: "hi, again"},
        twitter_post_options)

      assert_equal twitter_post_expected_header, header.to_s
    end

    # #rsa_sha1_signature tests

    def test_rsa_sha1_signature_reproduces_oauth_example_get
      header = SimpleOAuth::Header.new(:get, "http://photos.example.net/photos", {file: "vacaction.jpg", size: "original"},
        rsa_sha1_options)

      assert_equal rsa_sha1_expected_header, header.to_s
    end

    # #plaintext_signature tests

    def test_plaintext_signature_reproduces_oauth_example_get
      header = SimpleOAuth::Header.new(:get, "http://host.net/resource?name=value", {name: "value"}, plaintext_options)

      assert_equal plaintext_expected_header, header.to_s
    end

    private

    def twitter_get_options
      {
        consumer_key: "8karQBlMg6gFOwcf8kcoYw",
        consumer_secret: "3d0vcHyUiiqADpWxolW8nlDIpSWMlyK7YNgc5Qna2M",
        nonce: "547fed103e122eecf84c080843eedfe6",
        signature_method: "HMAC-SHA1",
        timestamp: "1286830180",
        token: "201425800-Sv4sTcgoffmHGkTCue0JnURT8vrm4DiFAkeFNDkh",
        token_secret: "T5qa1tF57tfDzKmpM89DHsNuhgOY4NT6DlNLsTFcuQ"
      }
    end

    def twitter_get_expected_header
      'OAuth oauth_consumer_key="8karQBlMg6gFOwcf8kcoYw", ' \
        'oauth_nonce="547fed103e122eecf84c080843eedfe6", oauth_signature="i9CT6ahDRAlfGX3hKYf78QzXsaw%3D", ' \
        'oauth_signature_method="HMAC-SHA1", oauth_timestamp="1286830180", ' \
        'oauth_token="201425800-Sv4sTcgoffmHGkTCue0JnURT8vrm4DiFAkeFNDkh", oauth_version="1.0"'
    end

    def twitter_post_options
      {
        consumer_key: "8karQBlMg6gFOwcf8kcoYw",
        consumer_secret: "3d0vcHyUiiqADpWxolW8nlDIpSWMlyK7YNgc5Qna2M",
        nonce: "b40a3e0f18590ecdcc0e273f7d7c82f8",
        signature_method: "HMAC-SHA1",
        timestamp: "1286830181",
        token: "201425800-Sv4sTcgoffmHGkTCue0JnURT8vrm4DiFAkeFNDkh",
        token_secret: "T5qa1tF57tfDzKmpM89DHsNuhgOY4NT6DlNLsTFcuQ"
      }
    end

    def twitter_post_expected_header
      'OAuth oauth_consumer_key="8karQBlMg6gFOwcf8kcoYw", ' \
        'oauth_nonce="b40a3e0f18590ecdcc0e273f7d7c82f8", oauth_signature="mPqSFKejrWWk3ZT9bTQjhO5b2xI%3D", ' \
        'oauth_signature_method="HMAC-SHA1", oauth_timestamp="1286830181", ' \
        'oauth_token="201425800-Sv4sTcgoffmHGkTCue0JnURT8vrm4DiFAkeFNDkh", oauth_version="1.0"'
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

    def rsa_sha1_expected_header
      'OAuth oauth_consumer_key="dpf43f3p2l4k3l03", oauth_nonce="13917289812797014437", ' \
        'oauth_signature="jvTp%2FwX1TYtByB1m%2BPbyo0lnCOLIsyGCH7wke8AUs3BpnwZJtAuEJkvQL2%2F9n4s5wUmUl4aCI4BwpraNx4RtEXMe' \
        '5qg5T1LVTGliMRpKasKsW%2F%2Fe%2BRinhejgCuzoH26dyF8iY2ZZ%2F5D1ilgeijhV%2FvBka5twt399mXwaYdCwFYE%3D", ' \
        'oauth_signature_method="RSA-SHA1", oauth_timestamp="1196666512", oauth_version="1.0"'
    end

    def plaintext_options
      {
        consumer_key: "abcd",
        consumer_secret: "efgh",
        nonce: "oLKtec51GQy",
        signature_method: "PLAINTEXT",
        timestamp: "1286977095",
        token: "ijkl",
        token_secret: "mnop"
      }
    end

    def plaintext_expected_header
      'OAuth oauth_consumer_key="abcd", oauth_nonce="oLKtec51GQy", oauth_signature="efgh%26mnop", ' \
        'oauth_signature_method="PLAINTEXT", oauth_timestamp="1286977095", oauth_token="ijkl", oauth_version="1.0"'
    end
  end
end
