require "test_helper"

module SimpleOAuth
  module OAuth2
    # Tests for revocation requests per RFC 7009 Section 2.1
    class ClientRevocationRequestTest < Minitest::Test
      include OAuth2Examples

      cover "SimpleOAuth::OAuth2::Client*"

      def test_matches_rfc_7009_example
        request = revoke_refresh_token

        assert_equal BASIC_AUTHORIZATION, request.headers["Authorization"]
        assert_equal "token=45ghiukldjahdnhzdauz&token_type_hint=refresh_token", request.body
      end

      def test_posts_to_the_revocation_endpoint
        request = revoke_refresh_token

        assert_equal "POST", request.method
        assert_equal REVOCATION_ENDPOINT, request.url
      end

      def test_from_a_public_client_without_a_hint
        request = public_client.revocation_request(token: ACCESS_TOKEN)

        assert_nil request.headers["Authorization"]
        assert_equal "token=#{ACCESS_TOKEN}&client_id=#{CLIENT_ID}", request.body
      end

      def test_requires_a_revocation_endpoint
        error = assert_raises(ArgumentError) do
          Client.new(client_id: CLIENT_ID).revocation_request(token: ACCESS_TOKEN)
        end

        assert_equal "The client has no revocation_endpoint", error.message
      end

      private

      def revoke_refresh_token
        confidential_client.revocation_request(token: "45ghiukldjahdnhzdauz", token_type_hint: "refresh_token")
      end
    end
  end
end
