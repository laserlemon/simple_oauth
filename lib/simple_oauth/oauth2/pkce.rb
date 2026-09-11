require "base64"
require "openssl"
require "securerandom"

module SimpleOAuth
  module OAuth2
    # A Proof Key for Code Exchange verifier and challenge, per RFC 7636
    #
    # @api public
    # @example Generate a verifier and use its challenge in an authorization URL
    #   pkce = SimpleOAuth::OAuth2::PKCE.generate
    #   client.authorization_url(redirect_uri: "https://app.example/cb", state: "xyz", pkce: pkce)
    class PKCE
      # Challenge method that hashes the verifier with SHA-256
      S256 = "S256".freeze
      # Challenge method that sends the verifier itself
      PLAIN = "plain".freeze
      # A valid verifier: 43 to 128 unreserved characters (RFC 7636 Section 4.1)
      VERIFIER_PATTERN = /\A[A-Za-z0-9\-._~]{43,128}\z/
      # The error message for an invalid verifier
      INVALID_VERIFIER = "PKCE verifier must be 43 to 128 unreserved characters".freeze
      # Random bytes in a generated verifier, which encode to 64 characters
      VERIFIER_BYTES = 48

      # The code verifier, sent with the token request
      #
      # @api public
      # @return [String] the code verifier
      # @example
      #   pkce.verifier # => "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
      attr_reader :verifier

      # The challenge method: S256 or plain
      #
      # @api public
      # @return [String] the challenge method
      # @example
      #   pkce.challenge_method # => "S256"
      attr_reader :challenge_method

      # The code challenge, sent with the authorization request
      #
      # @api public
      # @return [String] the code challenge
      # @example
      #   pkce.challenge # => "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuIJQj6wQFg"
      attr_reader :challenge

      # Generate a random verifier and its challenge
      #
      # @api public
      # @param challenge_method [String] the challenge method: S256 or plain
      # @return [PKCE] the verifier and challenge
      # @example
      #   SimpleOAuth::OAuth2::PKCE.generate
      def self.generate(challenge_method: S256)
        new(verifier: SecureRandom.urlsafe_base64(VERIFIER_BYTES), challenge_method:)
      end

      # Initialize from an existing verifier
      #
      # @api public
      # @param verifier [String] the code verifier
      # @param challenge_method [String] the challenge method: S256 or plain
      # @raise [ArgumentError] if the verifier or challenge method is invalid
      # @example
      #   SimpleOAuth::OAuth2::PKCE.new(verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
      def initialize(verifier:, challenge_method: S256)
        raise ArgumentError, INVALID_VERIFIER unless VERIFIER_PATTERN.match?(verifier)

        @verifier = verifier
        @challenge_method = challenge_method
        @challenge = compute_challenge
        freeze
      end

      private

      # Compute the challenge for the verifier with the challenge method
      #
      # @api private
      # @return [String] the code challenge
      # @raise [ArgumentError] if the challenge method is unknown
      def compute_challenge
        case challenge_method
        when S256 then Base64.urlsafe_encode64(OpenSSL::Digest.digest("SHA256", verifier), padding: false)
        when PLAIN then verifier
        else raise ArgumentError, "Unknown PKCE challenge method: #{challenge_method}"
        end
      end
    end
  end
end
