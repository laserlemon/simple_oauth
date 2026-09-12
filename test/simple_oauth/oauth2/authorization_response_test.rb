# frozen_string_literal: true

require "test_helper"

module SimpleOAuth
  module OAuth2
    # Tests for the authorization response a client receives at its redirect URI
    class AuthorizationResponseTest < Minitest::Test
      include OAuth2Examples

      cover "SimpleOAuth::OAuth2::AuthorizationResponse*"

      ISSUER = "https://server.example.com"

      def test_parse_reads_the_code_and_state
        # RFC 6749 Section 4.1.2 - the authorization response
        response = AuthorizationResponse.parse("code=#{CODE}&state=xyz", state: "xyz")

        assert_equal CODE, response.code
        assert_equal "xyz", response.state
      end

      def test_parse_accepts_parsed_parameters
        response = AuthorizationResponse.parse({"code" => CODE, "state" => "xyz"}, state: "xyz")

        assert_equal CODE, response.code
      end

      def test_parse_accepts_symbol_keys
        assert_equal CODE, AuthorizationResponse.parse({code: CODE}).code
      end

      def test_parse_without_an_expected_state_accepts_any
        assert_equal CODE, AuthorizationResponse.parse("code=#{CODE}&state=whatever").code
      end

      def test_parse_rejects_a_state_that_does_not_match
        error = assert_raises(Error) { AuthorizationResponse.parse("code=#{CODE}&state=other", state: "xyz") }

        assert_equal AuthorizationResponse::STATE_MISMATCH, error.description
        assert_nil error.code
      end

      def test_parse_rejects_a_missing_state_when_one_was_sent
        assert_raises(Error) { AuthorizationResponse.parse("code=#{CODE}", state: "xyz") }
      end

      def test_parse_reads_the_issuer
        # RFC 9207 Section 2 - the iss parameter
        response = AuthorizationResponse.parse("code=#{CODE}&iss=#{ISSUER}", issuer: ISSUER)

        assert_equal ISSUER, response.issuer
      end

      def test_parse_rejects_an_issuer_that_does_not_match
        error = assert_raises(Error) do
          AuthorizationResponse.parse("code=#{CODE}&iss=https://evil.example", issuer: ISSUER)
        end

        assert_equal AuthorizationResponse::ISSUER_MISMATCH, error.description
      end

      def test_parse_rejects_a_missing_issuer_when_one_is_expected
        assert_raises(Error) { AuthorizationResponse.parse("code=#{CODE}", issuer: ISSUER) }
      end

      def test_parse_without_an_expected_issuer_accepts_any
        assert_equal ISSUER, AuthorizationResponse.parse("code=#{CODE}&iss=#{ISSUER}").issuer
      end

      def test_parse_of_no_query_reports_no_code
        error = assert_raises(Error) { AuthorizationResponse.parse(nil) }

        assert_equal AuthorizationResponse::NO_CODE, error.description
      end
    end

    # Tests for the errors an authorization response reports or provokes
    class AuthorizationResponseErrorTest < Minitest::Test
      include OAuth2Examples

      cover "SimpleOAuth::OAuth2::AuthorizationResponse*"

      ISSUER = "https://server.example.com"

      def test_parse_raises_the_error_the_server_reported
        # RFC 6749 Section 4.1.2.1 - the error response
        error = assert_raises(Error) { AuthorizationResponse.parse("error=access_denied") }

        assert_equal "access_denied", error.code
      end

      def test_parse_carries_the_description_and_uri_of_the_reported_error
        error = assert_raises(Error) do
          AuthorizationResponse.parse("error=access_denied&error_description=Denied&error_uri=https://e/x")
        end

        assert_equal "Denied", error.description
        assert_equal "https://e/x", error.uri
      end

      def test_parse_prefers_the_reported_error_over_a_state_mismatch
        error = assert_raises(Error) { AuthorizationResponse.parse("error=access_denied&state=other", state: "xyz") }

        assert_equal "access_denied", error.code
      end

      def test_parse_rejects_a_response_with_no_code
        error = assert_raises(Error) { AuthorizationResponse.parse("state=xyz", state: "xyz") }

        assert_equal AuthorizationResponse::NO_CODE, error.description
      end

      def test_parse_rejects_an_empty_code
        assert_raises(Error) { AuthorizationResponse.parse("code=") }
      end

      def test_parse_rejects_a_repeated_parameter
        # RFC 6749 Section 3.1 - a parameter must not be included more than once
        error = assert_raises(Error) { AuthorizationResponse.parse("code=#{CODE}&code=other") }

        assert_equal AuthorizationResponse::DUPLICATE_PARAMETER, error.description
      end

      def test_parse_allows_a_repeated_parameter_in_parsed_parameters
        # A Hash cannot repeat a key, so there is nothing to check
        assert_equal CODE, AuthorizationResponse.parse({"code" => CODE}).code
      end

      def test_parse_keeps_every_parameter
        response = AuthorizationResponse.parse("code=#{CODE}&tenant=acme")

        assert_equal "acme", response.params["tenant"]
      end

      def test_matches_predicate
        assert AuthorizationResponse.matches?(nil, "anything")
        refute AuthorizationResponse.matches?("xyz", nil)
      end

      def test_frozen
        response = AuthorizationResponse.parse("code=#{CODE}")

        assert_predicate response, :frozen?
        assert_predicate response.params, :frozen?
      end

      def test_new_reads_a_code_given_with_a_symbol_key
        assert_equal CODE, AuthorizationResponse.new({code: CODE}).code
      end

      def test_new_reads_a_state_given_with_a_symbol_key
        assert_equal "xyz", AuthorizationResponse.new({code: CODE, state: "xyz"}).state
      end

      def test_parameters_accepts_a_hash_subclass
        subclass = Class.new(Hash).new
        subclass["code"] = CODE

        assert_equal({"code" => CODE}, AuthorizationResponse.parameters(subclass))
      end

      def test_reported_error_without_an_error_code
        assert_nil AuthorizationResponse.reported_error({}).code
      end

      def test_new_requires_a_code
        assert_raises(KeyError) { AuthorizationResponse.new({"state" => "xyz"}) }
      end

      def test_error_is_a_library_error
        assert_raises(SimpleOAuth::Error) { AuthorizationResponse.parse("code=a", state: "xyz") }
      end
    end
  end
end
