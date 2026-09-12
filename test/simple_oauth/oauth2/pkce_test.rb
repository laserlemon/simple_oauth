# frozen_string_literal: true

require "test_helper"

module SimpleOAuth
  module OAuth2
    # Tests for PKCE verifiers and challenges per RFC 7636
    class PKCETest < Minitest::Test
      include OAuth2Examples

      cover "SimpleOAuth::OAuth2::PKCE*"

      def test_s256_challenge_matches_rfc_7636_appendix_b
        pkce = PKCE.new(verifier: VERIFIER)

        assert_equal VERIFIER, pkce.verifier
        assert_equal CHALLENGE, pkce.challenge
        assert_equal "S256", pkce.challenge_method
      end

      def test_plain_challenge_is_the_verifier
        pkce = PKCE.new(verifier: VERIFIER, challenge_method: PKCE::PLAIN)

        assert_equal VERIFIER, pkce.challenge
        assert_equal "plain", pkce.challenge_method
      end

      def test_generate_creates_a_64_character_verifier
        pkce = PKCE.generate

        assert_equal 64, pkce.verifier.length
        assert_match PKCE::VERIFIER_PATTERN, pkce.verifier
      end

      def test_generate_creates_the_s256_challenge_of_its_verifier
        pkce = PKCE.generate

        assert_equal PKCE.new(verifier: pkce.verifier).challenge, pkce.challenge
        assert_equal "S256", pkce.challenge_method
      end

      def test_generate_creates_different_verifiers
        refute_equal PKCE.generate.verifier, PKCE.generate.verifier
      end

      def test_generate_with_plain_challenge_method
        pkce = PKCE.generate(challenge_method: PKCE::PLAIN)

        assert_equal pkce.verifier, pkce.challenge
      end

      def test_verifier_length_limits
        assert_equal 43, PKCE.new(verifier: "a" * 43).verifier.length
        assert_equal 128, PKCE.new(verifier: "a" * 128).verifier.length
      end

      def test_verifier_length_outside_limits
        assert_raises(ArgumentError) { PKCE.new(verifier: "a" * 42) }
        assert_raises(ArgumentError) { PKCE.new(verifier: "a" * 129) }
      end

      def test_verifier_must_use_unreserved_characters
        assert_equal "-._~", PKCE.new(verifier: "#{"a" * 40}-._~").verifier[-4..]
        error = assert_raises(ArgumentError) { PKCE.new(verifier: "#{"a" * 42}+") }

        assert_equal "PKCE verifier must be 43 to 128 unreserved characters", error.message
      end

      def test_verifier_must_not_end_with_a_newline
        assert_raises(ArgumentError) { PKCE.new(verifier: "#{"a" * 43}\n") }
      end

      def test_unknown_challenge_method
        error = assert_raises(ArgumentError) { PKCE.new(verifier: VERIFIER, challenge_method: "S512") }

        assert_equal "Unknown PKCE challenge method: S512", error.message
      end

      def test_frozen
        assert_predicate PKCE.new(verifier: VERIFIER), :frozen?
      end
    end
  end
end
