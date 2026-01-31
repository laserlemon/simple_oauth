require "base64"
require "cgi"
require "openssl"
require "securerandom"

module SimpleOAuth
  class Header
    # Class methods for Header - parsing, defaults, and body hashing
    #
    # @api private
    module ClassMethods
      # Returns default OAuth options with generated nonce and timestamp
      #
      # @api public
      # @param body [String, nil] optional request body for computing oauth_body_hash
      # @return [Hash] default options including nonce, signature_method, timestamp, and version
      # @example
      #   SimpleOAuth::Header.default_options
      #   # => {nonce: "abc123...", signature_method: "HMAC-SHA1", timestamp: "1234567890", version: "1.0"}
      def default_options(body = nil)
        {
          nonce: generate_nonce,
          signature_method: DEFAULT_SIGNATURE_METHOD,
          timestamp: Integer(Time.now).to_s,
          version: OAUTH_VERSION
        }.tap { |opts| opts[:body_hash] = body_hash(body) if body }
      end

      # Computes the oauth_body_hash for a request body
      #
      # @api public
      # @param body [String] the raw request body
      # @param algorithm [String] the hash algorithm to use (default: "SHA1")
      # @return [String] Base64-encoded hash of the body
      # @example
      #   SimpleOAuth::Header.body_hash('{"text": "Hello"}')
      #   # => "aOjMoMwMP1RZ0hKa1HryYDlCKck="
      def body_hash(body, algorithm = "SHA1")
        encode_base64(OpenSSL::Digest.digest(algorithm, body || ""))
      end

      # Parses an OAuth Authorization header string into a hash
      #
      # @api public
      # @param header [String, #to_s] the OAuth Authorization header string
      # @return [Hash] parsed OAuth attributes with symbol keys (only valid OAuth keys)
      # @raise [SimpleOAuth::ParseError] if the header is malformed
      # @example
      #   SimpleOAuth::Header.parse('OAuth oauth_consumer_key="key", oauth_signature="sig"')
      #   # => {consumer_key: "key", signature: "sig"}
      def parse(header)
        Parser.new(header).parse(PARSE_KEYS)
      end

      # Parses OAuth parameters from a form-encoded POST body
      #
      # OAuth 1.0 allows credentials to be transmitted in the request body for
      # POST requests with Content-Type: application/x-www-form-urlencoded
      #
      # @api public
      # @param body [String, #to_s] the form-encoded request body
      # @return [Hash] parsed OAuth attributes with symbol keys (only valid OAuth keys)
      # @example
      #   SimpleOAuth::Header.parse_form_body('oauth_consumer_key=key&oauth_signature=sig&status=hello')
      #   # => {consumer_key: "key", signature: "sig"}
      def parse_form_body(body)
        valid_keys = PARSE_KEYS.map(&:to_s)

        result = {} #: Hash[Symbol, String]
        CGI.parse(body.to_s).each do |key, values|
          next unless key.start_with?(OAUTH_PREFIX)

          parsed_key = key.delete_prefix(OAUTH_PREFIX)
          result[parsed_key.to_sym] = values.first || "" if valid_keys.include?(parsed_key)
        end
        result
      end

      private

      # Generates a random nonce for OAuth requests
      #
      # @api private
      # @return [String] hex-encoded random bytes
      def generate_nonce
        SecureRandom.hex
      end

      # Encodes binary data as Base64 without newlines
      #
      # @api private
      # @param data [String] binary data to encode
      # @return [String] Base64-encoded string
      def encode_base64(data)
        Base64.strict_encode64(data)
      end
    end
  end
end
