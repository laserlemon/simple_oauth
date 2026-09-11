require "cgi"

module SimpleOAuth
  class Header
    # Normalization of the request parameters that are signed, per RFC 5849 Section 3.4.1.3
    #
    # @api private
    module Params
      private

      # Extracts valid OAuth attributes from options
      #
      # @api private
      # @return [Hash] OAuth attributes without signature or realm
      def attributes
        validate_option_keys!
        options.slice(*ATTRIBUTE_KEYS).transform_keys { |key| :"#{OAUTH_PREFIX}#{key}" }
      end

      # Validates that no unknown keys are present in options
      #
      # @api private
      # @raise [InvalidOptionsError] if extra keys are found
      # @return [void]
      def validate_option_keys!
        return if options[:ignore_extra_keys]

        extra_keys = options.keys - ATTRIBUTE_KEYS - IGNORED_KEYS
        return if extra_keys.empty?

        raise InvalidOptionsError, "Unknown option keys: #{extra_keys.map(&:inspect).join(", ")}"
      end

      # Extracts query parameters from the request URL
      #
      # @api private
      # @return [Array<Array>] URL query parameters as key-value pairs
      def url_params
        CGI.parse(@uri.query || "").flat_map do |key, values|
          values.sort.map { |value| [key, value] }
        end
      end

      # Normalizes and sorts all request parameters for signing
      #
      # @api private
      # @return [String] normalized request parameters
      def normalized_params
        signature_params
          .map { |key, value| [Header.escape(key), Header.escape(value)] }
          .sort
          .map { |pair| pair.join("=") }
          .join("&")
      end

      # Collects all parameters to include in signature
      #
      # @api private
      # @return [Array<Array>] all parameters for signature as key-value pairs
      def signature_params
        attributes.to_a + expanded_params + url_params
      end

      # Expands parameters into one pair per value, for parameters with several values
      #
      # @api private
      # @return [Array<Array(Object, Object)>] the parameter pairs
      def expanded_params
        params.flat_map do |key, value|
          value.is_a?(Array) ? value.map { |element| [key, element] } : [[key, value]]
        end
      end
    end
  end
end
