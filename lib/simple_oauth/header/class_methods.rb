require "uri"
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
      # @param signature_method [String] the signature method, whose hash algorithm oauth_body_hash uses
      # @return [Hash] default options including nonce, signature_method, timestamp, and version
      # @example
      #   SimpleOAuth::Header.default_options
      #   # => {nonce: "abc123...", signature_method: "HMAC-SHA1", timestamp: "1234567890", version: "1.0"}
      def default_options(body = nil, signature_method = DEFAULT_SIGNATURE_METHOD)
        {
          nonce: generate_nonce,
          signature_method: signature_method,
          timestamp: Integer(Time.now).to_s,
          version: OAUTH_VERSION
        }.tap { |opts| opts[:body_hash] = body_hash(body, Signature.digest(signature_method)) if body }
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
        Signature.encode_base64(OpenSSL::Digest.digest(algorithm, body || ""))
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

      # Builds a header for an HTTP request, signing the parameters it carries
      #
      # The request's query parameters are always signed. A form-encoded body is signed as
      # parameters, and any other body is hashed into oauth_body_hash.
      #
      # @api public
      # @param request [#method, #uri, #body] the request to sign, such as a Net::HTTPRequest
      # @param oauth [Hash, String] OAuth options hash or an existing Authorization header to parse
      # @return [Header] the header for the request
      # @raise [ArgumentError] if the request has no URI
      # @example
      #   request = Net::HTTP::Post.new(URI("https://api.example.com/statuses"))
      #   request.set_form_data(status: "Hello")
      #   request["Authorization"] = SimpleOAuth::Header.from_request(request,
      #     consumer_key: "key", consumer_secret: "secret").to_s
      def from_request(request, oauth = {})
        uri = request.uri || raise(ArgumentError, "The request has no URI")
        body = request.body
        return new(request.method, uri, form_pairs(body), oauth) if form_encoded?(request)

        no_params = {} #: Header::request_params
        new(request.method, uri, no_params, oauth, body)
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
      # @example Parse the credentials from a query string
      #   SimpleOAuth::Header.parse_query('oauth_consumer_key=key&status=hello')
      #   # => {consumer_key: "key"}
      def parse_form_body(body)
        valid_keys = PARSE_KEYS.map(&:to_s)

        result = {} #: Hash[Symbol, String]
        form_pairs(body).each do |key, value|
          next unless key.start_with?(OAUTH_PREFIX)

          parsed_key = key.delete_prefix(OAUTH_PREFIX)
          # ||= so that the first value wins when a parameter repeats
          result[parsed_key.to_sym] ||= value if valid_keys.include?(parsed_key)
        end
        result
      end

      # @!method parse_query(query)
      #   Parses OAuth parameters from a query string, which RFC 5849 Section 3.5.3 also allows
      #
      #   @api public
      #   @param query [String, #to_s] the query string
      #   @return [Hash] parsed OAuth attributes with symbol keys (only valid OAuth keys)
      #   @example
      #     SimpleOAuth::Header.parse_query("oauth_consumer_key=key&status=hello")
      #     # => {consumer_key: "key"}
      alias_method :parse_query, :parse_form_body

      # Parses a form-encoded query string or body into parameter pairs
      #
      # A parameter with no value, such as the "c2" of the RFC 5849 Section 3.4.1.3.1
      # example, carries an empty value rather than being dropped. An empty segment, as in
      # the "&&" of "a=1&&b=2", is no parameter at all. Only "&" separates parameters: a
      # ";" is part of the value, as every current server reads it.
      #
      # @api private
      # @param form [String, #to_s, nil] the form-encoded query string or body
      # @return [Array<Array(String, String)>] the parameter pairs
      # @example
      #   SimpleOAuth::Header.form_pairs("c2&a3=2+q")
      #   # => [["c2", ""], ["a3", "2 q"]]
      def form_pairs(form)
        URI.decode_www_form(form.to_s).reject { |key, value| key.empty? && value.empty? }
      end

      private

      # Checks whether a request carries a form-encoded body
      #
      # @api private
      # @param request [#[]] the request
      # @return [Boolean] true if the body is form-encoded
      def form_encoded?(request)
        media_type(request).eql?(FORM_CONTENT_TYPE)
      end

      # Extracts the media type from a request, without its parameters
      #
      # Per RFC 9110 Section 8.3 the media type is case-insensitive and may carry parameters,
      # such as a charset, that play no part in identifying it.
      #
      # @api private
      # @param request [#[]] the request
      # @return [String] the lowercase media type, or an empty String when the request declares none
      def media_type(request)
        request["Content-Type"].to_s.split(";").first.to_s.strip.downcase
      end

      # Generates a random nonce for OAuth requests
      #
      # @api private
      # @return [String] hex-encoded random bytes
      def generate_nonce
        SecureRandom.hex
      end
    end
  end
end
