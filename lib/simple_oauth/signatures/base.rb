module Signatures
  module Base
    def create(consumer_secret, token_secret, base)
      @consumer_secret, @token_secret = consumer_secret, token_secret
      ::Base64.encode64(digest(secret, base)).chomp.delete("\n")
    end

    def escape(value)
      uri_parser.escape(value.to_s, /[^a-z0-9\-\.\_\~]/i)
    end
    alias encode escape

    def unescape(value)
      uri_parser.unescape(value.to_s)
    end
    alias decode unescape

  protected

    def secret
      [@consumer_secret, @token_secret].collect { |v| escape(v) }.join('&')
    end

    # alias_method :plaintext_signature, :secret
    def uri_parser
      @uri_parser ||= URI.const_defined?(:Parser) ? URI::Parser.new : URI
    end

    def digest(_secret, _base)
      raise NotImplementedError
    end
  end
end
