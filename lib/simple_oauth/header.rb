require "uri"
require_relative "encoding"
require_relative "errors"
require_relative "parser"
require_relative "signature"
require_relative "header/class_methods"
require_relative "header/params"

module SimpleOAuth
  # Generates OAuth 1.0 Authorization headers for HTTP requests
  #
  # @api public
  class Header
    # OAuth header scheme prefix
    OAUTH_SCHEME = "OAuth".freeze

    # Prefix for OAuth parameters
    OAUTH_PREFIX = "oauth_".freeze

    # The content type whose body parameters are signed, per RFC 5849 Section 3.4.1.3.1
    FORM_CONTENT_TYPE = "application/x-www-form-urlencoded".freeze
    # Default signature method per RFC 5849
    DEFAULT_SIGNATURE_METHOD = "HMAC-SHA1".freeze

    # OAuth version
    OAUTH_VERSION = "1.0".freeze

    # Valid OAuth attribute keys that can be included in the header
    ATTRIBUTE_KEYS = %i[body_hash callback consumer_key nonce signature_method timestamp token verifier version].freeze

    # Keys that are used internally but should not appear in attributes
    IGNORED_KEYS = %i[consumer_secret token_secret signature realm ignore_extra_keys].freeze

    # Valid keys when parsing OAuth parameters (ATTRIBUTE_KEYS + signature)
    PARSE_KEYS = [*ATTRIBUTE_KEYS, :signature].freeze

    # The HTTP method for the request
    #
    # @return [String] the HTTP method (GET, POST, etc.)
    # @example
    #   header.method # => "GET"
    attr_reader :method

    # The request parameters to be signed
    #
    # @return [Hash, Array<Array(String, Object)>] the request parameters
    # @example
    #   header.params # => {"status" => "Hello"}
    attr_reader :params

    # The raw request body for oauth_body_hash computation
    #
    # @return [String, nil] the request body
    # @example
    #   header.body # => '{"text": "Hello"}'
    attr_reader :body

    # The OAuth options including credentials and signature
    #
    # @return [Hash] the OAuth options
    # @example
    #   header.options # => {consumer_key: "key", nonce: "..."}
    attr_reader :options

    include Params

    extend ClassMethods
    extend Encoding

    # Creates a new OAuth header
    #
    # @api public
    # @param method [String, Symbol] the HTTP method
    # @param url [String, URI] the request URL
    # @param params [Hash, Array<Array(String, Object)>] the request parameters (for form-encoded bodies),
    #   as a Hash or as an Array of key-value pairs when a key repeats
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
      @uri = normalize_uri(url)
      @params = params
      @body = body
      @options = build_options(oauth, body)
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
      @uri.dup.tap { |uri| uri.query = nil }.to_str
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
      "#{OAUTH_SCHEME} #{normalized_attributes}"
    end

    # Validates the signature in the header against the provided secrets
    #
    # @api public
    # @param secrets [Hash] the consumer_secret and token_secret for validation
    # @return [Boolean] true if the signature is valid, false otherwise
    # @note When the header was built with a body, the signed oauth_body_hash must match that body,
    #   so a tampered body fails verification even though its signature covers the claimed hash
    # @example
    #   parsed_header = SimpleOAuth::Header.new(:get, url, {}, authorization_header)
    #   parsed_header.valid?(consumer_secret: "secret", token_secret: "token_secret")
    #   # => true
    def valid?(secrets = {})
      body_hash_valid? && Signature.verify(options.fetch(:signature_method), signing_key(options.merge(secrets)),
        signature_base, options.fetch(:signature))
    end

    # Returns the OAuth attributes including the signature
    #
    # @api public
    # @return [Hash] OAuth attributes with oauth_signature included
    # @example
    #   header.signed_attributes
    #   # => {oauth_consumer_key: "key", oauth_signature: "...", ...}
    def signed_attributes
      header_attributes.merge(oauth_signature: signature)
    end

    private

    # Normalizes and parses a URL into a URI object
    #
    # @api private
    # @param url [String, URI] the URL to normalize
    # @return [URI::Generic] normalized URI without fragment
    def normalize_uri(url)
      URI.parse(url.to_s).tap do |uri|
        uri.normalize!
        uri.fragment = nil
      end
    end

    # Builds OAuth options from input (hash or header string)
    #
    # @api private
    # @param oauth [Hash, String] OAuth options hash or Authorization header
    # @param body [String, nil] request body for body_hash computation
    # @return [Hash] merged OAuth options with defaults
    def build_options(oauth, body)
      return self.class.parse(oauth) unless oauth.is_a?(Hash)

      overrides = oauth.transform_keys(&:to_sym)
      self.class.default_options(body, overrides.fetch(:signature_method, DEFAULT_SIGNATURE_METHOD)).merge(overrides)
    end

    # Builds the normalized OAuth attributes string for the header
    #
    # @api private
    # @return [String] normalized OAuth attributes for the header
    def normalized_attributes
      signed_attributes
        .sort_by { |key, _| key }
        .map { |key, value| "#{key}=\"#{Header.escape(value)}\"" }
        .join(", ")
    end

    # Returns OAuth attributes with realm for the Authorization header
    #
    # Per RFC 5849 Section 3.5.1, realm is included in the Authorization header
    # but excluded from signature calculation (Section 3.4.1.3.1)
    #
    # @api private
    # @return [Hash] OAuth attributes with realm if present
    def header_attributes
      attrs = attributes
      attrs[:realm] = options.fetch(:realm) if options[:realm]
      attrs
    end

    # Computes the OAuth signature using the configured method
    #
    # @api private
    # @return [String] the computed signature based on signature_method
    def signature
      Signature.sign(options.fetch(:signature_method), signing_key(options), signature_base)
    end

    # The key for signing and verifying: an RSA key, or the escaped secrets
    #
    # @api private
    # @param options [Hash] the options holding the credentials
    # @return [String, nil] the key
    def signing_key(options)
      Signature.rsa?(options.fetch(:signature_method)) ? options[:consumer_secret] : secret(options)
    end

    # Checks the body against the oauth_body_hash the header carries
    #
    # A header parsed from a request claims a body hash that its signature covers, so the claim must be
    # checked against the body actually received. A signer that omits oauth_body_hash leaves the body
    # unprotected, which its signature already attests to, so there is nothing to check.
    #
    # @api private
    # @return [Boolean] true unless the body contradicts the signed oauth_body_hash
    def body_hash_valid?
      claimed_body_hash = options[:body_hash]
      return true if body.nil? || claimed_body_hash.nil?

      digest = Signature.digest(options.fetch(:signature_method))
      OpenSSL.secure_compare(self.class.body_hash(body, digest), claimed_body_hash)
    end

    # Builds the secret string from consumer and token secrets
    #
    # @api private
    # @param options [Hash] the options holding the secrets
    # @return [String] the secret string for signing
    def secret(options)
      options.values_at(:consumer_secret, :token_secret).map { |v| Header.escape(v) }.join("&")
    end

    # Builds the signature base string from method, URL, and params
    #
    # @api private
    # @return [String] the signature base string
    def signature_base
      [method, url, normalized_params].map { |v| Header.escape(v) }.join("&")
    end
  end
end
