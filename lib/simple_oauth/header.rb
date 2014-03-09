require 'openssl'
require 'uri'
require 'base64'
require 'cgi'

module SimpleOAuth
  class ParseError < StandardError; end

  class Header
    ATTRIBUTE_KEYS = [:callback, :consumer_key, :nonce, :signature_method, :timestamp, :token, :verifier, :version] unless defined? ::SimpleOAuth::Header::ATTRIBUTE_KEYS
    HEADER_KEYS = ATTRIBUTE_KEYS + [:signature]
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
        header = header.to_s
        if header =~ /^OAuth\s/
          header = $'
        else
          raise ParseError, "Received non-OAuth header: #{header}"
        end
        header.split(/,\s*/).inject({}) do |attributes, pair|
          match = pair.match(/^oauth_(\w+)\=\"([^\"]*)\"$/)
          if match
            key_s = match[1]
            # use a symbol only when the parameter is a recognized header key
            key = HEADER_KEYS.detect { |k| k.to_s == key_s } || key_s
            attributes.merge(key => unescape(match[2]))
          else
            raise ParseError, "invalid: #{pair}"
          end
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
      attributes.to_a + params.to_a + url_params
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
