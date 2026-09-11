require "json"

module SimpleOAuth
  module OAuth2
    # Parses the JSON bodies returned by OAuth 2.0 endpoints
    #
    # @api private
    module ResponseBody
      # Parse a response body into a Hash, or an empty Hash if it is not a JSON object
      #
      # @api private
      # @param body [String, nil] the response body
      # @return [Hash{String => Object}] the parsed object
      # @example
      #   SimpleOAuth::OAuth2::ResponseBody.parse('{"error":"invalid_grant"}')
      #   # => {"error" => "invalid_grant"}
      def self.parse(body)
        Hash.try_convert(JSON.parse(body.to_s)) || {}
      rescue JSON::ParserError
        {}
      end
    end
  end
end
