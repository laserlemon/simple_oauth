require "base64"
require "cgi"
require "openssl"
require "securerandom"
require "uri"
require_relative "encoding"
require_relative "signature"

# OAuth 1.0 header generation library
module SimpleOAuth
  # Generates OAuth 1.0 Authorization headers for HTTP requests
  #
  # @api public
  class Header
    # Valid OAuth attribute keys that can be included in the header
    ATTRIBUTE_KEYS = %i[body_hash callback consumer_key nonce signature_method timestamp token verifier version].freeze

    # Keys that are used internally but should not appear in attributes
    IGNORED_KEYS = %i[consumer_secret token_secret signature realm].freeze

    # Valid keys when parsing OAuth parameters (ATTRIBUTE_KEYS + signature)
    PARSE_KEYS = (ATTRIBUTE_KEYS + %i[signature]).freeze

    # The HTTP method for the request
    #
    # @return [String] the HTTP method (GET, POST, etc.)
    # @api public
    # @example
    #   header.method
    #   # => "GET"
    attr_reader :method

    # The request parameters to be signed
    #
    # @return [Hash] the request parameters
    # @api public
    # @example
    #   header.params
    #   # => {status: "Hello"}
    attr_reader :params

    # The raw request body for oauth_body_hash computation
    #
    # @return [String, nil] the raw request body
    # @api public
    # @example
    #   header.body
    #   # => '{"text": "Hello"}'
    attr_reader :body

    # The OAuth options including credentials and signature
    #
    # @return [Hash] the OAuth options
    # @api public
    # @example
    #   header.options
    #   # => {consumer_key: "key", nonce: "...", ...}
    attr_reader :options

    class << self
      # Returns default OAuth options with generated nonce and timestamp
      #
      # @api public
      # @param body [String, nil] optional request body for computing oauth_body_hash
      # @return [Hash] default options including nonce, signature_method, timestamp, and version
      # @example
      #   SimpleOAuth::Header.default_options
      #   # => {nonce: "abc123...", signature_method: "HMAC-SHA1", timestamp: "1234567890", version: "1.0"}
      # @example With body for oauth_body_hash
      #   SimpleOAuth::Header.default_options('{"text": "Hello"}')
      #   # => {nonce: "abc123...", signature_method: "HMAC-SHA1", timestamp: "1234567890", version: "1.0", body_hash: "..."}
      def default_options(body = nil)
        options = {
          nonce: Random.random_bytes.unpack1("H*"),
          signature_method: "HMAC-SHA1",
          timestamp: Integer(Time.now).to_s,
          version: "1.0"
        }
        options[:body_hash] = body_hash(body) if body
        options
      end

      # Computes the oauth_body_hash for a request body
      #
      # @api public
      # @param body [String] the raw request body
      # @param hash_algorithm [String] the hash algorithm to use (default: "SHA1")
      # @return [String] Base64-encoded hash of the body
      # @example
      #   SimpleOAuth::Header.body_hash('{"text": "Hello"}')
      #   # => "aOjMoMwMP1RZ0hKa1HryYDlCKck="
      def body_hash(body, hash_algorithm = "SHA1")
        Base64.encode64(OpenSSL::Digest.digest(hash_algorithm, body || "")).delete("\n")
      end

      # Parses an OAuth Authorization header string into a hash
      #
      # @api public
      # @param header [String, #to_s] the OAuth Authorization header string
      # @return [Hash] parsed OAuth attributes with symbol keys (only valid OAuth keys)
      # @example
      #   SimpleOAuth::Header.parse('OAuth oauth_consumer_key="key", oauth_signature="sig"')
      #   # => {consumer_key: "key", signature: "sig"}
      def parse(header)
        header.to_s.sub(/\AOAuth\s/, "").split(/,\s*/).each_with_object(Hash.new) do |pair, attributes| # rubocop:disable Style/EmptyLiteral
          match = pair.match(/\A(\w+)="([^"]*)"\z/) or next
          key = match[1].delete_prefix("oauth_").to_sym
          attributes[key] = unescape(match[2]) if PARSE_KEYS.include?(key)
        end
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
        CGI.parse(body.to_s).each_with_object(Hash.new) do |(key, values), attributes| # rubocop:disable Style/EmptyLiteral
          next unless key.start_with?("oauth_")

          parsed_key = key.delete_prefix("oauth_").to_sym
          attributes[parsed_key] = values.first || "" if PARSE_KEYS.include?(parsed_key)
        end
      end
    end

    # Add escape/unescape/encode/decode class methods from Encoding module
    extend Encoding

    # Creates a new OAuth header
    #
    # @api public
    # @param method [String, Symbol] the HTTP method
    # @param url [String, URI] the request URL
    # @param params [Hash] the request parameters (for form-encoded bodies)
    # @param oauth [Hash, String] OAuth options hash or an existing Authorization header to parse
    # @param body [String, nil] raw request body for oauth_body_hash (for non-form-encoded bodies)
    # @example Create a header with OAuth options
    #   SimpleOAuth::Header.new(:get, "https://api.example.com/resource", {},
    #     consumer_key: "key", consumer_secret: "secret")
    # @example Create a header by parsing an existing Authorization header
    #   SimpleOAuth::Header.new(:get, "https://api.example.com/resource", {}, existing_header)
    # @example Create a header with a JSON body (oauth_body_hash will be computed)
    #   SimpleOAuth::Header.new(:post, "https://api.example.com/resource", {},
    #     {consumer_key: "key", consumer_secret: "secret"}, '{"text": "Hello"}')
    def initialize(method, url, params, oauth = {}, body = nil)
      @method = method.to_s.upcase
      @uri = URI.parse(url.to_s)
      @uri.normalize!
      @uri.fragment = nil
      @params = params
      @body = body
      @options = oauth.is_a?(Hash) ? self.class.default_options(body).merge(oauth.transform_keys(&:to_sym)) : self.class.parse(oauth)
    end

    # Returns the normalized URL without query string or fragment
    #
    # @api public
    # @return [String] the normalized URL
    # @example
    #   header = SimpleOAuth::Header.new(:get, "https://api.example.com/path?query=1", {})
    #   header.url
    #   # => "https://api.example.com/path"
    def url
      uri = @uri.dup
      uri.query = nil
      uri.to_str
    end

    # Returns the OAuth Authorization header string
    #
    # @api public
    # @return [String] the Authorization header value
    # @example
    #   header = SimpleOAuth::Header.new(:get, "https://api.example.com/", {},
    #     consumer_key: "key", consumer_secret: "secret")
    #   header.to_s
    #   # => "OAuth oauth_consumer_key=\"key\", oauth_nonce=\"...\", ..."
    def to_s
      "OAuth #{normalized_attributes}"
    end

    # Validates the signature in the header against the provided secrets
    #
    # @api public
    # @param secrets [Hash] the consumer_secret and token_secret for validation
    # @return [Boolean] true if the signature is valid, false otherwise
    # @example
    #   parsed_header = SimpleOAuth::Header.new(:get, url, {}, authorization_header)
    #   parsed_header.valid?(consumer_secret: "secret", token_secret: "token_secret")
    #   # => true
    def valid?(secrets = {})
      original_options = options.dup
      options.merge!(secrets)
      valid = options.fetch(:signature).eql?(signature)
      options.replace(original_options)
      valid
    end

    # Returns the OAuth attributes including the signature
    #
    # @api public
    # @return [Hash] OAuth attributes with oauth_signature included
    # @example
    #   header.signed_attributes
    #   # => {oauth_consumer_key: "key", oauth_signature: "...", ...}
    def signed_attributes
      attributes.merge(oauth_signature: signature)
    end

    private

    # Builds the normalized OAuth attributes string for the Authorization header
    #
    # @api private
    # @return [String] normalized OAuth attributes for the header
    def normalized_attributes
      signed_attributes.sort_by { |k, _| k }.collect { |k, v| %(#{k}="#{self.class.escape(v)}") }.join(", ")
    end

    # Extracts valid OAuth attributes from options
    #
    # @api private
    # @return [Hash] OAuth attributes without signature
    def attributes
      extra_keys = options.keys - ATTRIBUTE_KEYS - IGNORED_KEYS
      raise_extra_keys_error(extra_keys) unless options[:ignore_extra_keys] || extra_keys.empty?
      attrs = options.slice(*ATTRIBUTE_KEYS).transform_keys { |key| :"oauth_#{key}" }
      realm = options[:realm]
      attrs[:realm] = realm if realm
      attrs
    end

    # Raises an error for invalid extra keys in options
    #
    # @api private
    # @raise [RuntimeError] always raises with list of extra keys
    # @return [void]
    def raise_extra_keys_error(extra_keys)
      raise "SimpleOAuth: Found extra option keys not matching ATTRIBUTE_KEYS:\n  [#{extra_keys.collect(&:inspect).join(", ")}]"
    end

    # Computes the OAuth signature using the configured signature method
    #
    # @api private
    # @return [String] the computed signature based on signature_method
    def signature
      sig_method = options.fetch(:signature_method)
      sig_secret = Signature.rsa?(sig_method) ? options[:consumer_secret] : secret
      Signature.sign(sig_method, sig_secret, signature_base)
    end

    # Builds the secret string from consumer and token secrets
    #
    # @api private
    # @return [String] the secret string for signing
    def secret
      options.values_at(:consumer_secret, :token_secret).collect { |v| self.class.escape(v) }.join("&")
    end

    # Builds the signature base string from method, URL, and params
    #
    # @api private
    # @return [String] the signature base string
    def signature_base
      [method, url, normalized_params].collect { |v| self.class.escape(v) }.join("&")
    end

    # Normalizes and sorts all request parameters for signing
    #
    # @api private
    # @return [String] normalized request parameters
    def normalized_params
      signature_params.collect { |p| p.collect { |v| self.class.escape(v) } }.sort.collect { |p| p.join("=") }.join("&")
    end

    # Collects all parameters to include in signature
    #
    # @api private
    # @return [Array] all parameters for signature
    def signature_params
      attributes.to_a + params.to_a + url_params
    end

    # Extracts query parameters from the request URL
    #
    # @api private
    # @return [Array] URL query parameters as key-value pairs
    def url_params
      CGI.parse(@uri.query || "").inject([]) { |p, (k, vs)| p + vs.sort.collect { |v| [k, v] } }
    end
  end
end
