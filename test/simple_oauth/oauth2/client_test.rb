require "test_helper"

module SimpleOAuth
  module OAuth2
    # Tests for OAuth 2.0 client configuration
    class ClientTest < Minitest::Test
      include OAuth2Examples

      cover "SimpleOAuth::OAuth2::Client*"

      def test_credentials
        client = confidential_client

        assert_equal CLIENT_ID, client.client_id
        assert_equal CLIENT_SECRET, client.client_secret
        assert_equal :client_secret_basic, client.auth_method
      end

      def test_endpoints
        client = confidential_client

        assert_equal AUTHORIZATION_ENDPOINT, client.authorization_endpoint
        assert_equal TOKEN_ENDPOINT, client.token_endpoint
        assert_equal REVOCATION_ENDPOINT, client.revocation_endpoint
      end

      def test_optional_settings_default_to_nil
        client = Client.new(client_id: CLIENT_ID)

        assert_nil client.client_secret
        assert_nil client.authorization_endpoint
        assert_nil client.revocation_endpoint
      end

      def test_token_endpoint_defaults_to_nil
        assert_nil Client.new(client_id: CLIENT_ID).token_endpoint
      end

      def test_public
        assert_predicate public_client, :public?
        refute_predicate confidential_client, :public?
      end

      def test_client_secret_post
        assert_equal :client_secret_post, confidential_client(auth_method: :client_secret_post).auth_method
      end

      def test_unknown_auth_method
        error = assert_raises(ArgumentError) { confidential_client(auth_method: :private_key_jwt) }

        assert_equal "Unknown auth_method: :private_key_jwt", error.message
      end

      def test_frozen
        assert_predicate confidential_client, :frozen?
      end
    end
  end
end
