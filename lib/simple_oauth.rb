require 'base64'
require 'cgi'
require 'openssl'
require 'uri'

module SimpleOAuth
  class Header
    ATTRIBUTE_KEYS = [:consumer_key, :nonce, :signature, :signature_method, :timestamp, :token, :version]

    def self.default_options
      {
        :nonce => OpenSSL::Random.random_bytes(16).unpack('H*')[0],
        :signature_method => 'HMAC-SHA1',
        :timestamp => Time.now.to_i.to_s,
        :version => '1.0'
      }
    end

    def self.encode(value)
      URI.encode(value.to_s, /[^\w\-\.\~]/)
    end

    attr_reader :method, :params, :options

    def initialize(method, url, params, options = {})
      @method = method.to_s.upcase
      @uri = URI.parse(url).normalize
      @params = params
      @options = self.class.default_options.merge(options)
    end

    def to_s
      @to_s ||= "OAuth #{normalized_attributes}"
    end

    def url
      @url ||= @uri.dup.tap{|u| u.query = nil }.to_s
    end

    private
      def normalized_attributes
        signed_attributes.sort_by(&:to_s).map{|k,v| %(#{k}="#{self.class.encode(v)}") }.join(', ')
      end

      def signed_attributes
        attributes.merge(:oauth_signature => signature)
      end

      def attributes
        ATTRIBUTE_KEYS.inject({}){|a,k| options.key?(k) ? a.merge(:"oauth_#{k}" => options[k]) : a }
      end

      def signature
        send(options[:signature_method].downcase.tr('-', '_') + '_signature')
      end

      def hmac_sha1_signature
        Base64.encode64(OpenSSL::HMAC.digest(OpenSSL::Digest::Digest.new('sha1'), secret, signature_base)).chomp
      end

      def rsa_sha1_signature
        Base64.encode64(OpenSSL::HMAC.digest(OpenSSL::Digest::Digest.new('sha1'), options[:private_key], signature_base)).chomp
      end

      def secret
        options.values_at(:consumer_secret, :token_secret).map{|v| self.class.encode(v) }.join('&')
      end

      alias_method :plaintext_signature, :secret

      def signature_base
        [method, url, normalized_params].map{|v| self.class.encode(v) }.join('&')
      end

      def normalized_params
        signature_params.sort_by(&:to_s).map{|p| p.map{|v| self.class.encode(v) }.join('=') }.join('&')
      end

      def signature_params
        attributes.to_a + params.to_a + url_params.to_a
      end

      def url_params
        CGI.parse(@uri.query || '')
      end
  end
end
