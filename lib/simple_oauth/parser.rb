require "strscan"

module SimpleOAuth
  # Parses OAuth Authorization headers
  #
  # @api private
  class Parser
    # Pattern to match OAuth key-value pairs: key="value", or key="value"
    PARAM_PATTERN = /(\w+)="([^"]*)"\s*(,?)\s*/

    # The StringScanner instance for parsing the header
    #
    # @return [StringScanner] the scanner
    attr_reader :scanner

    # The parsed OAuth attributes
    #
    # @return [Hash{Symbol => String}] the parsed attributes
    attr_reader :attributes

    # Creates a new Parser for the given header string
    #
    # @param header [String, #to_s] the OAuth Authorization header string
    # @return [Parser] a new parser instance
    def initialize(header)
      @scanner = StringScanner.new(header.to_s)
      @attributes = {} # : Hash[Symbol, String]
    end

    # Parses the OAuth Authorization header
    #
    # @param valid_keys [Array<Symbol>] the valid OAuth parameter keys
    # @return [Hash{Symbol => String}] the parsed attributes
    # @raise [SimpleOAuth::ParseError] if the header is malformed
    def parse(valid_keys)
      scan_oauth_prefix
      scan_params(valid_keys)
      verify_complete
      attributes
    end

    private

    # Scans and validates the OAuth prefix
    #
    # @return [void]
    # @raise [SimpleOAuth::ParseError] if the header doesn't start with "OAuth "
    def scan_oauth_prefix
      scanner.scan(/OAuth\s+/) or raise ParseError, "Authorization header must start with 'OAuth '"
    end

    # Scans all key-value parameters from the header
    #
    # @param valid_keys [Array<Symbol>] the valid OAuth parameter keys
    # @return [void]
    def scan_params(valid_keys)
      while scanner.scan(PARAM_PATTERN)
        key = scanner[1] #: String
        value = scanner[2] #: String
        comma = scanner[3] #: String
        validate_comma_separator(key, comma)
        store_if_valid(key, value, valid_keys)
      end
    end

    # Validates that a comma separator exists between parameters
    #
    # @param key [String] the parameter key for error messages
    # @param comma [String] the comma separator (empty string if missing)
    # @return [void]
    # @raise [SimpleOAuth::ParseError] if comma is missing and more content follows
    def validate_comma_separator(key, comma)
      return if !comma.empty? || scanner.eos?

      raise ParseError,
        "Expected comma after '#{key}' parameter at position #{scanner.pos}: #{scanner.rest.inspect}"
    end

    # Stores the parameter if it's a valid OAuth key
    #
    # @param key [String] the raw parameter key
    # @param value [String] the parameter value
    # @param valid_keys [Array<Symbol>] the valid OAuth parameter keys
    # @return [void]
    def store_if_valid(key, value, valid_keys)
      parsed_key = valid_keys.detect { |k| "oauth_#{k}".eql?(key) }
      attributes[parsed_key] = Header.unescape(value) if parsed_key
    end

    # Verifies that the entire header was parsed
    #
    # @return [void]
    # @raise [SimpleOAuth::ParseError] if unparsed content remains
    def verify_complete
      return if scanner.eos?

      raise ParseError,
        "Could not parse parameter at position #{scanner.pos}: #{scanner.rest.inspect}"
    end
  end
end
