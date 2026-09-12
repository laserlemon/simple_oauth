require "test_helper"

module SimpleOAuth
  module OAuth2
    # Tests for token requests per RFC 6749 Sections 4.1.3, 4.4.2, and 6
    class ClientTokenRequestTest < Minitest::Test
      include OAuth2Examples

      cover "SimpleOAuth::OAuth2::Client*"

      FORM_HEADERS = {"Content-Type" => "application/x-www-form-urlencoded", "Accept" => "application/json"}.freeze
      ENCODED_REDIRECT_URI = "https%3A%2F%2Fclient.example.com%2Fcb".freeze

      def test_authorization_code_request_matches_rfc_6749_example
        request = confidential_client.authorization_code_request(code: CODE, redirect_uri: REDIRECT_URI)

        assert_equal FORM_HEADERS.merge("Authorization" => BASIC_AUTHORIZATION), request.headers
        assert_equal "grant_type=authorization_code&code=#{CODE}&redirect_uri=#{ENCODED_REDIRECT_URI}", request.body
      end

      def test_token_requests_post_to_the_token_endpoint
        request = confidential_client.authorization_code_request(code: CODE, redirect_uri: REDIRECT_URI)

        assert_equal "POST", request.method
        assert_equal TOKEN_ENDPOINT, request.url
      end

      def test_authorization_code_request_from_a_public_client_with_pkce
        request = public_client.authorization_code_request(code: CODE, redirect_uri: REDIRECT_URI,
          code_verifier: VERIFIER)

        assert_equal FORM_HEADERS, request.headers
        assert_equal "grant_type=authorization_code&code=#{CODE}&redirect_uri=#{ENCODED_REDIRECT_URI}" \
                     "&code_verifier=#{VERIFIER}&client_id=#{CLIENT_ID}", request.body
      end

      def test_client_secret_post_sends_credentials_in_the_body
        client = confidential_client(auth_method: :client_secret_post)
        request = client.refresh_token_request(refresh_token: REFRESH_TOKEN)

        assert_equal FORM_HEADERS, request.headers
        assert_equal "grant_type=refresh_token&refresh_token=#{REFRESH_TOKEN}&client_id=#{CLIENT_ID}" \
                     "&client_secret=#{CLIENT_SECRET}", request.body
      end

      def test_refresh_token_request_matches_rfc_6749_example
        request = confidential_client.refresh_token_request(refresh_token: REFRESH_TOKEN)

        assert_equal BASIC_AUTHORIZATION, request.headers["Authorization"]
        assert_equal "grant_type=refresh_token&refresh_token=#{REFRESH_TOKEN}", request.body
      end

      def test_refresh_token_request_with_a_narrower_scope
        request = confidential_client.refresh_token_request(refresh_token: REFRESH_TOKEN,
          scope: %w[tweet.read users.read])

        assert_equal "grant_type=refresh_token&refresh_token=#{REFRESH_TOKEN}&scope=tweet.read+users.read", request.body
      end

      def test_client_credentials_request_matches_rfc_6749_example
        request = confidential_client.client_credentials_request

        assert_equal TOKEN_ENDPOINT, request.url
        assert_equal BASIC_AUTHORIZATION, request.headers["Authorization"]
        assert_equal "grant_type=client_credentials", request.body
      end

      def test_client_credentials_request_with_scope
        assert_equal "grant_type=client_credentials&scope=a+b",
          confidential_client.client_credentials_request(scope: "a b").body
      end

      def test_request_without_a_scope_omits_it
        assert_equal "grant_type=client_credentials", confidential_client.client_credentials_request.body
      end

      def test_request_with_an_empty_scope_omits_it
        assert_equal "grant_type=client_credentials",
          confidential_client.client_credentials_request(scope: "").body
      end

      def test_request_with_an_empty_scope_list_omits_it
        assert_equal "grant_type=client_credentials",
          confidential_client.client_credentials_request(scope: []).body
      end

      def test_client_credentials_request_with_a_scope_list
        assert_equal "grant_type=client_credentials&scope=a+b",
          confidential_client.client_credentials_request(scope: %w[a b]).body
      end

      def test_client_credentials_request_requires_a_secret
        error = assert_raises(ArgumentError) { public_client.client_credentials_request }

        assert_equal "The client credentials grant requires a client secret", error.message
      end

      def test_basic_credentials_are_form_encoded_first
        client = Client.new(client_id: "a b", client_secret: "c:d", token_endpoint: TOKEN_ENDPOINT)

        assert_equal "Basic #{["a+b:c%3Ad"].pack("m0")}", client.client_credentials_request.headers["Authorization"]
      end

      def test_requires_a_token_endpoint
        error = assert_raises(ArgumentError) do
          Client.new(client_id: CLIENT_ID).refresh_token_request(refresh_token: REFRESH_TOKEN)
        end

        assert_equal "The client has no token_endpoint", error.message
      end
    end
  end
end
