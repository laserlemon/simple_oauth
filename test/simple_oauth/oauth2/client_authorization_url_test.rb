require "test_helper"

module SimpleOAuth
  module OAuth2
    # Tests for authorization URLs per RFC 6749 Section 4.1.1 and RFC 7636 Section 4.3
    class ClientAuthorizationURLTest < Minitest::Test
      include OAuth2Examples

      cover "SimpleOAuth::OAuth2::Client*"

      def test_rfc_6749_example
        url = confidential_client.authorization_url(redirect_uri: REDIRECT_URI, state: "xyz")

        assert_equal "#{AUTHORIZATION_ENDPOINT}?response_type=code&client_id=#{CLIENT_ID}" \
                     "&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb&state=xyz", url
      end

      def test_scope_list_is_space_delimited
        url = public_client.authorization_url(redirect_uri: REDIRECT_URI, state: "xyz",
          scope: %w[tweet.read users.read])

        assert_includes url, "&scope=tweet.read+users.read&state=xyz"
      end

      def test_scope_string_is_sent_as_is
        url = public_client.authorization_url(redirect_uri: REDIRECT_URI, state: "xyz", scope: "offline.access")

        assert_includes url, "&scope=offline.access&state=xyz"
      end

      def test_pkce_challenge
        url = public_client.authorization_url(redirect_uri: REDIRECT_URI, state: "xyz",
          pkce: PKCE.new(verifier: VERIFIER))

        assert url.end_with?("&state=xyz&code_challenge=#{CHALLENGE}&code_challenge_method=S256")
      end

      def test_additional_params
        url = public_client.authorization_url(redirect_uri: REDIRECT_URI, state: "xyz",
          params: {prompt: "consent", nonce: nil})

        assert url.end_with?("&state=xyz&prompt=consent")
      end

      def test_endpoint_with_a_query
        client = Client.new(client_id: CLIENT_ID, authorization_endpoint: "#{AUTHORIZATION_ENDPOINT}?tenant=a")
        url = client.authorization_url(redirect_uri: REDIRECT_URI, state: "xyz")

        assert url.start_with?("#{AUTHORIZATION_ENDPOINT}?tenant=a&response_type=code&")
      end

      def test_requires_an_authorization_endpoint
        error = assert_raises(ArgumentError) do
          Client.new(client_id: CLIENT_ID).authorization_url(redirect_uri: REDIRECT_URI, state: "xyz")
        end

        assert_equal "The client has no authorization_endpoint", error.message
      end
    end
  end
end
