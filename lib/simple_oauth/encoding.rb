require "uri"

module SimpleOAuth
  # OAuth percent-encoding utilities
  #
  # Provides methods for encoding and decoding values according to the OAuth specification.
  # These methods can be used as module functions or extended into a class.
  #
  # @api public
  module Encoding
    # Percent-encodes a value according to OAuth specification
    #
    # @api public
    # @param value [String, #to_s] the value to encode
    # @return [String] the percent-encoded value
    # @example
    #   SimpleOAuth::Encoding.escape("hello world")
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
    #   SimpleOAuth::Encoding.unescape("hello%20world")
    #   # => "hello world"
    def unescape(value)
      URI::RFC2396_PARSER.unescape(value.to_s)
    end
    alias_method :decode, :unescape

    # Allow calling as SimpleOAuth::Encoding.escape directly
  end
end
