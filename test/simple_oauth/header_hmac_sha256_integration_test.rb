require "test_helper"

module SimpleOAuth
  class HeaderHmacSha256IntegrationTest < Minitest::Test
    cover "SimpleOAuth::Header*"

    def test_hmac_sha256_signature_produces_valid_signature_for_get
      header = SimpleOAuth::Header.new(:get, "https://api.twitter.com/1/statuses/friends.json", {}, twitter_get_options)

      assert_equal twitter_get_expected_header, header.to_s
    end

    def test_hmac_sha256_signature_produces_valid_signature_for_post
      header = SimpleOAuth::Header.new(:post, "https://api.twitter.com/1/statuses/update.json", {status: "hi, again"},
        twitter_post_options)

      assert_equal twitter_post_expected_header, header.to_s
    end

    private

    def twitter_get_options
      {
        consumer_key: "8karQBlMg6gFOwcf8kcoYw",
        consumer_secret: "3d0vcHyUiiqADpWxolW8nlDIpSWMlyK7YNgc5Qna2M",
        nonce: "547fed103e122eecf84c080843eedfe6",
        signature_method: "HMAC-SHA256",
        timestamp: "1286830180",
        token: "201425800-Sv4sTcgoffmHGkTCue0JnURT8vrm4DiFAkeFNDkh",
        token_secret: "T5qa1tF57tfDzKmpM89DHsNuhgOY4NT6DlNLsTFcuQ"
      }
    end

    def twitter_get_expected_header
      'OAuth oauth_consumer_key="8karQBlMg6gFOwcf8kcoYw", ' \
        'oauth_nonce="547fed103e122eecf84c080843eedfe6", oauth_signature="PNzEtEcjBwCTw36Msb0dYCVwXPGZqaapda%2BFAXzznHg%3D", ' \
        'oauth_signature_method="HMAC-SHA256", oauth_timestamp="1286830180", ' \
        'oauth_token="201425800-Sv4sTcgoffmHGkTCue0JnURT8vrm4DiFAkeFNDkh", oauth_version="1.0"'
    end

    def twitter_post_options
      {
        consumer_key: "8karQBlMg6gFOwcf8kcoYw",
        consumer_secret: "3d0vcHyUiiqADpWxolW8nlDIpSWMlyK7YNgc5Qna2M",
        nonce: "b40a3e0f18590ecdcc0e273f7d7c82f8",
        signature_method: "HMAC-SHA256",
        timestamp: "1286830181",
        token: "201425800-Sv4sTcgoffmHGkTCue0JnURT8vrm4DiFAkeFNDkh",
        token_secret: "T5qa1tF57tfDzKmpM89DHsNuhgOY4NT6DlNLsTFcuQ"
      }
    end

    def twitter_post_expected_header
      'OAuth oauth_consumer_key="8karQBlMg6gFOwcf8kcoYw", ' \
        'oauth_nonce="b40a3e0f18590ecdcc0e273f7d7c82f8", oauth_signature="b5mVSdq8H8R7jMnmLiylxCqlxKoKWC3T9CpGk3zDmIg%3D", ' \
        'oauth_signature_method="HMAC-SHA256", oauth_timestamp="1286830181", ' \
        'oauth_token="201425800-Sv4sTcgoffmHGkTCue0JnURT8vrm4DiFAkeFNDkh", oauth_version="1.0"'
    end
  end
end
