require "base64"
require "cgi"
require "openssl"
require "securerandom"
require "uri"

# OAuth 1.0 header generation library
module SimpleOAuth
  # Generates OAuth 1.0 Authorization headers for HTTP requests
  #
  # @api public
  class Header
    # Valid OAuth attribute keys that can be included in the header
    ATTRIBUTE_KEYS = %i[callback consumer_key nonce signature_method timestamp token verifier version].freeze

    # Keys that are used internally but should not appear in attributes
    IGNORED_KEYS = %i[consumer_secret token_secret signature].freeze

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
      # @return [Hash] default options including nonce, signature_method, timestamp, and version
      # @example
      #   SimpleOAuth::Header.default_options
      #   # => {nonce: "abc123...", signature_method: "HMAC-SHA1", timestamp: "1234567890", version: "1.0"}
      def default_options
        {
          nonce: Random.random_bytes.unpack1("H*"),
          signature_method: "HMAC-SHA1",
          timestamp: Integer(Time.now).to_s,
          version: "1.0"
        }
      end

      # Parses an OAuth Authorization header string into a hash
      #
      # @api public
      # @param header [String, #to_s] the OAuth Authorization header string
      # @return [Hash] parsed OAuth attributes with symbol keys
      # @example
      #   SimpleOAuth::Header.parse('OAuth oauth_consumer_key="key", oauth_signature="sig"')
      #   # => {consumer_key: "key", signature: "sig"}
      def parse(header)
        header.to_s.sub(/\AOAuth\s/, "").split(/,\s*/).each_with_object(Hash.new) do |pair, attributes| # rubocop:disable Style/EmptyLiteral
          match = pair.match(/\A(\w+)="([^"]*)"\z/) or next
          attributes[match[1].delete_prefix("oauth_").to_sym] = unescape(match[2])
        end
      end

      # Percent-encodes a value according to OAuth specification
      #
      # @api public
      # @param value [String, #to_s] the value to encode
      # @return [String] the percent-encoded value
      # @example
      #   SimpleOAuth::Header.escape("hello world")
      #   # => "hello%20world"
      def escape(value)
        URI::RFC2396_PARSER.escape(value.to_s, /[^a-z0-9\-._~]/i)
      end
      alias_method :encode, :escape

      # Decodes a percent-encoded value
      #
      # @api public
      # @param value [String, #to_s] the value to decode
      # @return [String] the decoded value
      # @example
      #   SimpleOAuth::Header.unescape("hello%20world")
      #   # => "hello world"
      def unescape(value)
        URI::RFC2396_PARSER.unescape(value.to_s)
      end
      alias_method :decode, :unescape
    end

    # Creates a new OAuth header
    #
    # @api public
    # @param method [String, Symbol] the HTTP method
    # @param url [String, URI] the request URL
    # @param params [Hash] the request parameters
    # @param oauth [Hash, String] OAuth options hash or an existing Authorization header to parse
    # @example Create a header with OAuth options
    #   SimpleOAuth::Header.new(:get, "https://api.example.com/resource", {},
    #     consumer_key: "key", consumer_secret: "secret")
    # @example Create a header by parsing an existing Authorization header
    #   SimpleOAuth::Header.new(:get, "https://api.example.com/resource", {}, existing_header)
    def initialize(method, url, params, oauth = {})
      @method = method.to_s.upcase
      @uri = URI.parse(url.to_s)
      @uri.normalize!
      @uri.fragment = nil
      @params = params
      @options = oauth.is_a?(Hash) ? self.class.default_options.merge(oauth) : self.class.parse(oauth)
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
      matching_keys, extra_keys = options.keys.partition { |key| ATTRIBUTE_KEYS.include?(key) }
      extra_keys -= IGNORED_KEYS
      unless options[:ignore_extra_keys] || extra_keys.empty?
        raise "SimpleOAuth: Found extra option keys not matching ATTRIBUTE_KEYS:\n  [#{extra_keys.collect(&:inspect).join(", ")}]"
      end

      options.slice(*matching_keys).transform_keys { |key| :"oauth_#{key}" }
    end

    # Computes the OAuth signature using the configured signature method
    #
    # @api private
    # @return [String] the computed signature based on signature_method
    def signature
      __send__("#{options.fetch(:signature_method).downcase.tr("-", "_")}_signature")
    end

    # Computes HMAC-SHA1 signature
    #
    # @api private
    # @return [String] HMAC-SHA1 signature
    def hmac_sha1_signature
      Base64.encode64(OpenSSL::HMAC.digest("SHA1", secret, signature_base)).delete("\n")
    end

    # Builds the secret string from consumer and token secrets
    #
    # @api private
    # @return [String] the secret string for signing
    def secret
      options.values_at(:consumer_secret, :token_secret).collect { |v| self.class.escape(v) }.join("&")
    end
    # @!method plaintext_signature
    #   Returns the PLAINTEXT signature (same as secret)
    #   @api private
    #   @return [String] the PLAINTEXT signature
    alias_method :plaintext_signature, :secret

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

    # Computes RSA-SHA1 signature using private key
    #
    # @api private
    # @return [String] RSA-SHA1 signature
    def rsa_sha1_signature
      Base64.encode64(private_key.sign("SHA1", signature_base)).delete("\n")
    end

    # Parses the RSA private key from consumer_secret
    #
    # @api private
    # @return [OpenSSL::PKey::RSA] the RSA private key
    def private_key
      OpenSSL::PKey::RSA.new(options[:consumer_secret])
    end
  end
end
