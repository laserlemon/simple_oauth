require "uri"

module SimpleOAuth
  # OAuth percent-encoding utilities
  #
  # Provides methods for encoding and decoding values according to the OAuth specification.
  # These methods can be used as module functions or extended into a class.
  #
  # @api public
  # @example Using as module functions
  #   SimpleOAuth::Encoding.escape("hello world") # => "hello%20world"
  #
  # @example Extending into a class
  #   class MyClass
  #     extend SimpleOAuth::Encoding
  #   end
  #   MyClass.escape("hello world") # => "hello%20world"
  module Encoding
    # Characters that don't need to be escaped per OAuth spec
    UNRESERVED_CHARS = /[^a-z0-9\-._~]/i

    # Percent-encodes a value according to OAuth specification
    #
    # @api public
    # @param value [String, #to_s] the value to encode
    # @return [String] the percent-encoded value
    # @example
    #   SimpleOAuth::Encoding.escape("hello world")
    #   # => "hello%20world"
    def escape(value)
      URI::RFC2396_PARSER.escape(value.to_s, UNRESERVED_CHARS)
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
  end
end
