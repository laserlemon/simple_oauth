require_relative "../errors"
require_relative "response_body"

module SimpleOAuth
  module OAuth2
    # Error returned by an OAuth 2.0 endpoint, per RFC 6749 Section 5.2
    #
    # @api public
    # @example Raise the error described by a failed response
    #   raise SimpleOAuth::OAuth2::Error.from_response(status: 400, body: '{"error":"invalid_grant"}')
    class Error < SimpleOAuth::Error
      # The error message for a status that is not an HTTP status
      INVALID_STATUS = "The status must be an Integer or a String of digits".freeze

      # The error code, such as invalid_grant, if the response included one
      #
      # @api public
      # @return [String, nil] the error code
      # @example
      #   error.code # => "invalid_grant"
      attr_reader :code

      # The human-readable description from the endpoint
      #
      # @api public
      # @return [String, nil] the description
      # @example
      #   error.description # => "The refresh token is invalid"
      attr_reader :description

      # The URI of a page describing the error
      #
      # @api public
      # @return [String, nil] the error URI
      # @example
      #   error.uri # => "https://example.com/errors/invalid_grant"
      attr_reader :uri

      # The HTTP status of the response
      #
      # @api public
      # @return [Integer, nil] the HTTP status
      # @example
      #   error.status # => 400
      attr_reader :status

      # The HTTP status of a response, as an Integer
      #
      # @api private
      # @param value [Integer, String] the status of the response
      # @return [Integer] the status
      # @raise [ArgumentError] if the value is not an HTTP status
      # @example
      #   SimpleOAuth::OAuth2::Error.http_status("400") # => 400
      def self.http_status(value)
        Integer(value, exception: false) || raise(ArgumentError, "#{INVALID_STATUS}: #{value.inspect}")
      end

      # Build the error described by an OAuth 2.0 error response
      #
      # @api public
      # @param status [Integer, String] the HTTP status of the response
      # @param body [String, nil] the response body
      # @return [Error] the error
      # @raise [ArgumentError] if the status is not an HTTP status
      # @example
      #   SimpleOAuth::OAuth2::Error.from_response(status: 400, body: '{"error":"invalid_grant"}')
      def self.from_response(status:, body:)
        params = ResponseBody.parse(body)
        new(code: params["error"], description: params["error_description"], uri: params["error_uri"],
          status: http_status(status))
      end

      # Initialize a new error
      #
      # @api public
      # @param code [String, nil] the error code
      # @param description [String, nil] the human-readable description
      # @param uri [String, nil] the URI of a page describing the error
      # @param status [Integer, nil] the HTTP status of the response
      # @example
      #   SimpleOAuth::OAuth2::Error.new(code: "invalid_grant", status: 400)
      def initialize(code:, description: nil, uri: nil, status: nil)
        @code = code
        @description = description
        @uri = uri
        @status = status
        details = [code, description].compact
        super(details.empty? ? "OAuth 2.0 request failed with status #{status}" : details.join(": "))
      end
    end
  end
end
