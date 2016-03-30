require 'cgi'
require 'simple_oauth/signatures'

module SimpleOAuth
  class Header
    extend Signatures::Base

    ATTRIBUTE_KEYS = [:callback, :consumer_key, :nonce, :signature_method, :timestamp, :token, :verifier, :version].freeze unless defined? ::SimpleOAuth::Header::ATTRIBUTE_KEYS
    IGNORED_KEYS = [:consumer_secret, :token_secret, :signature].freeze unless defined? ::SimpleOAuth::Header::IGNORED_KEYS

    attr_reader :method, :params, :options

    class << self
      def default_options
        {
          :nonce => OpenSSL::Random.random_bytes(16).unpack('H*')[0],
          :signature_method => 'HMAC-SHA1',
          :timestamp => Time.now.to_i.to_s,
          :version => '1.0',
        }
      end

      def parse(header)
        header.to_s.sub(/^OAuth\s/, '').split(/,\s*/).inject({}) do |attributes, pair|
          match = pair.match(/^(\w+)\=\"([^\"]*)\"$/)
          attributes.merge(match[1].sub(/^oauth_/, '').to_sym => unescape(match[2]))
        end
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
      signed_attributes.sort_by { |k, _| k.to_s }.collect { |k, v| %(#{k}="#{self.class.escape(v)}") }.join(', ')
    end

    def attributes
      matching_keys, extra_keys = options.keys.partition { |key| ATTRIBUTE_KEYS.include?(key) }
      extra_keys -= IGNORED_KEYS
      if options[:ignore_extra_keys] || extra_keys.empty?
        Hash[options.select { |key, _| matching_keys.include?(key) }.collect { |key, value| [:"oauth_#{key}", value] }]
      else
        raise "SimpleOAuth: Found extra option keys not matching ATTRIBUTE_KEYS:\n  [#{extra_keys.collect(&:inspect).join(', ')}]"
      end
    end

    def signature
      Signatures::ENCODERS[options[:signature_method]].create(options[:consumer_secret], options[:token_secret], signature_base)
    end

    def signature_base
      [method, url, normalized_params].collect { |v| self.class.escape(v) }.join('&')
    end

    def normalized_params
      signature_params.collect { |p| p.collect { |v| self.class.escape(v) } }.sort.collect { |p| p.join('=') }.join('&')
    end

    def signature_params
      attributes.to_a + params.to_a + url_params
    end

    def url_params
      CGI.parse(@uri.query || '').inject([]) { |p, (k, vs)| p + vs.sort.collect { |v| [k, v] } }
    end
  end
end
