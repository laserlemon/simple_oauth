require 'openssl'
require 'uri'
require 'base64'
require 'cgi'

module SimpleOAuth
  class Header
    ATTRIBUTE_KEYS = [:callback, :consumer_key, :nonce, :signature_method, :timestamp, :token, :verifier, :version] unless defined? ::SimpleOAuth::Header::ATTRIBUTE_KEYS
    attr_reader :method, :params, :options

    class << self
      def default_options
        {
          :nonce => OpenSSL::Random.random_bytes(16).unpack('H*')[0],
          :signature_method => 'HMAC-SHA1',
          :timestamp => Time.now.to_i.to_s,
          :version => '1.0'
        }
      end

      def parse(header)
        header.to_s.sub(/^OAuth\s/, '').split(/,\s*/).inject({}) do |attributes, pair|
          match = pair.match(/^(\w+)\=\"([^\"]*)\"$/)
          attributes.merge(match[1].sub(/^oauth_/, '').to_sym => unescape(match[2]))
        end
      end

      def escape(value)
        uri_parser.escape(value.to_s, /[^a-z0-9\-\.\_\~]/i)
      end
      alias encode escape

      def unescape(value)
        uri_parser.unescape(value.to_s)
      end
      alias decode unescape

      def stretch_params(params)
        result = []

        params.each do |key, value|
          case value
          when Array
            value.each { |array_value| result += stretch_params [[key, array_value]] }
          when Hash
            prefixed_params = value.map { |k, v| ["#{key.to_s}[#{k.to_s}]", v] }
            inner_result = stretch_params(prefixed_params)

            # Stable sort. We want to preserve sorting of inner arrays
            n = 0
            result += inner_result.sort_by { |k, _| n += 1; [k.to_s, n] }
          else
            result << [key, value]
          end
        end

        result
      end

    private

      def uri_parser
        @uri_parser ||= URI.const_defined?(:Parser) ? URI::Parser.new : URI
      end

    end

    def initialize(method, url, params, oauth = {})
      @method = method.to_s.upcase
      @uri = URI.parse(url.to_s)
      @uri.scheme = @uri.scheme.downcase
      @uri.normalize!
      @uri.fragment = nil
      @params = params
      @options = oauth.is_a?(Hash) ? self.class.default_options.merge(oauth) : self.class.parse(oauth)
    end

    def url
      uri = @uri.dup
      uri.query = nil
      uri.to_s
    end

    def to_s
      "OAuth #{normalized_attributes}"
    end

    def valid?(secrets = {})
      original_options = options.dup
      options.merge!(secrets)
      valid = options[:signature] == signature
      options.replace(original_options)
      valid
    end

    def signed_attributes
      attributes.merge(:oauth_signature => signature)
    end

  private

    def normalized_attributes
      signed_attributes.sort_by{|k,v| k.to_s }.map{|k,v| %(#{k}="#{self.class.escape(v)}") }.join(', ')
    end

    def attributes
      ATTRIBUTE_KEYS.inject({}){|a,k| options[k] ? a.merge(:"oauth_#{k}" => options[k]) : a }
    end

    def signature
      send(options[:signature_method].downcase.tr('-', '_') + '_signature')
    end

    def hmac_sha1_signature
      Base64.encode64(OpenSSL::HMAC.digest(OpenSSL::Digest::SHA1.new, secret, signature_base)).chomp.gsub(/\n/, '')
    end

    def secret
      options.values_at(:consumer_secret, :token_secret).map{|v| self.class.escape(v) }.join('&')
    end
    alias_method :plaintext_signature, :secret

    def signature_base
      [method, url, normalized_params].map{|v| self.class.escape(v) }.join('&')
    end

    def normalized_params
      signature_params.map{|p| p.map{|v| self.class.escape(v) } }.sort.map{|p| p.join('=') }.join('&')
    end

    def signature_params
      self.class.stretch_params(attributes.to_a + params.to_a + url_params)
    end

    def url_params
      CGI.parse(@uri.query || '').inject([]){|p,(k,vs)| p + vs.sort.map{|v| [k, v] } }
    end

    def rsa_sha1_signature
      Base64.encode64(private_key.sign(OpenSSL::Digest::SHA1.new, signature_base)).chomp.gsub(/\n/, '')
    end

    def private_key
      OpenSSL::PKey::RSA.new(options[:consumer_secret])
    end

  end
end
