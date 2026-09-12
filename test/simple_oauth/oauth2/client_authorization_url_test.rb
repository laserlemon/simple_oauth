# frozen_string_literal: true

require "test_helper"

module SimpleOAuth
  module OAuth2
    # Tests for authorization URLs per RFC 6749 Section 4.1.1 and RFC 7636 Section 4.3
    class ClientAuthorizationURLTest < Minitest::Test
      include OAuth2Examples

      cover "SimpleOAuth::OAuth2::Client*"

      def test_rfc_6749_example
        url = confidential_client.authorization_url(redirect_uri: REDIRECT_URI, pkce: nil, state: "xyz")

        assert_equal "#{AUTHORIZATION_ENDPOINT}?response_type=code&client_id=#{CLIENT_ID}" \
                     "&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb&state=xyz", url
      end

      def test_scope_list_is_space_delimited
        url = public_client.authorization_url(redirect_uri: REDIRECT_URI, pkce: nil, state: "xyz",
          scope: %w[tweet.read users.read])

        assert_includes url, "&scope=tweet.read+users.read&state=xyz"
      end

      def test_extra_params_with_a_string_key_override_rather_than_repeat
        url = public_client.authorization_url(redirect_uri: REDIRECT_URI, pkce: nil, state: "xyz",
          params: {"state" => "other"})

        assert_includes url, "state=other"
        refute_includes url, "state=xyz"
      end

      def test_extra_params_with_a_symbol_key_override
        url = public_client.authorization_url(redirect_uri: REDIRECT_URI, pkce: nil, state: "xyz",
          params: {response_type: "token"})

        assert_includes url, "response_type=token"
        refute_includes url, "response_type=code"
      end

      def test_empty_scope_is_omitted
        url = public_client.authorization_url(redirect_uri: REDIRECT_URI, pkce: nil, state: "xyz", scope: [])

        refute_includes url, "scope"
      end

      def test_scope_string_is_sent_as_is
        url = public_client.authorization_url(redirect_uri: REDIRECT_URI, pkce: nil, state: "xyz",
          scope: "offline.access")

        assert_includes url, "&scope=offline.access&state=xyz"
      end

      def test_pkce_challenge
        url = public_client.authorization_url(redirect_uri: REDIRECT_URI, state: "xyz",
          pkce: PKCE.new(verifier: VERIFIER))

        assert url.end_with?("&state=xyz&code_challenge=#{CHALLENGE}&code_challenge_method=S256")
      end

      def test_additional_params
        url = public_client.authorization_url(redirect_uri: REDIRECT_URI, pkce: nil, state: "xyz",
          params: {prompt: "consent", nonce: nil})

        assert url.end_with?("&state=xyz&prompt=consent")
      end

      def test_endpoint_with_a_query
        client = Client.new(client_id: CLIENT_ID, authorization_endpoint: "#{AUTHORIZATION_ENDPOINT}?tenant=a")
        url = client.authorization_url(redirect_uri: REDIRECT_URI, pkce: nil, state: "xyz")

        assert url.start_with?("#{AUTHORIZATION_ENDPOINT}?tenant=a&response_type=code&")
      end

      def test_requires_a_pkce_or_a_state
        error = assert_raises(ArgumentError) do
          public_client.authorization_url(redirect_uri: REDIRECT_URI, pkce: nil, state: nil)
        end

        assert_equal Client::UNPROTECTED, error.message
      end

      def test_requires_a_state_that_is_not_empty
        error = assert_raises(ArgumentError) do
          public_client.authorization_url(redirect_uri: REDIRECT_URI, pkce: nil, state: "")
        end

        assert_equal Client::EMPTY_STATE, error.message
      end

      def test_an_empty_state_is_rejected_even_with_a_pkce
        assert_raises(ArgumentError) do
          public_client.authorization_url(redirect_uri: REDIRECT_URI, pkce: PKCE.generate, state: "")
        end
      end

      def test_a_pkce_stands_in_for_the_state
        # OAuth 2.1 ties the response to the request with the PKCE challenge
        url = public_client.authorization_url(redirect_uri: REDIRECT_URI, pkce: PKCE.new(verifier: VERIFIER))

        assert_includes url, "code_challenge=#{CHALLENGE}"
        refute_includes url, "state="
      end

      def test_a_state_and_a_pkce_are_both_sent
        url = public_client.authorization_url(redirect_uri: REDIRECT_URI, pkce: PKCE.new(verifier: VERIFIER),
          state: "xyz")

        assert_includes url, "state=xyz"
        assert_includes url, "code_challenge_method=S256"
      end

      def test_omitting_the_pkce_builds_the_oauth_2_0_url
        # An OAuth 2.0 authorization server that rejects the challenge parameters still works
        url = public_client.authorization_url(redirect_uri: REDIRECT_URI, pkce: nil, state: "xyz")

        refute_includes url, "code_challenge"
        assert_includes url, "state=xyz"
      end

      def test_requires_an_authorization_endpoint
        error = assert_raises(ArgumentError) do
          Client.new(client_id: CLIENT_ID).authorization_url(redirect_uri: REDIRECT_URI, pkce: nil, state: "xyz")
        end

        assert_equal "The client has no authorization_endpoint", error.message
      end
    end
  end
end
