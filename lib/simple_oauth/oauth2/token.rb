require_relative "error"
require_relative "response_body"

module SimpleOAuth
  module OAuth2
    # An access token from a successful token response, per RFC 6749 Section 5.1
    #
    # @api public
    # @example Parse a token response
    #   token = SimpleOAuth::OAuth2::Token.from_response(status: 200, body: response_body)
    #   token.access_token # => "2YotnFZFEjr1zCsicMWpAA"
    class Token
      # The access token
      #
      # @api public
      # @return [String] the access token
      # @example
      #   token.access_token # => "2YotnFZFEjr1zCsicMWpAA"
      attr_reader :access_token

      # The token type, such as bearer
      #
      # @api public
      # @return [String, nil] the token type
      # @example
      #   token.token_type # => "bearer"
      attr_reader :token_type

      # The lifetime of the access token in seconds
      #
      # @api public
      # @return [Integer, nil] the lifetime in seconds
      # @example
      #   token.expires_in # => 3600
      attr_reader :expires_in

      # The refresh token, if one was issued
      #
      # @api public
      # @return [String, nil] the refresh token
      # @example
      #   token.refresh_token # => "tGzv3JOkF0XG5Qx2TlKWIA"
      attr_reader :refresh_token

      # The granted scope, as a space-delimited string
      #
      # @api public
      # @return [String, nil] the granted scope
      # @example
      #   token.scope # => "tweet.read users.read"
      attr_reader :scope

      # The time when the access token expires
      #
      # @api public
      # @return [Time, nil] the expiration time
      # @example
      #   token.expires_at # => 2026-09-11 13:00:00 UTC
      attr_reader :expires_at

      # Every parameter of the token response, including nonstandard ones
      #
      # @api public
      # @return [Hash{String => Object}] the parameters
      # @example
      #   token.params["example_parameter"] # => "example_value"
      attr_reader :params

      # Parse a token response, raising the endpoint's error if it failed
      #
      # @api public
      # @param status [Integer, String] the HTTP status of the response
      # @param body [String, nil] the response body
      # @param issued_at [Time] when the token was issued, used to compute its expiration
      # @return [Token] the token
      # @raise [Error] if the response is not successful or has no access token
      # @example
      #   SimpleOAuth::OAuth2::Token.from_response(status: 200, body: '{"access_token":"abc","token_type":"bearer"}')
      def self.from_response(status:, body:, issued_at: Time.now)
        raise Error.from_response(status:, body:) unless (200..299).cover?(Integer(status))

        params = ResponseBody.parse(body)
        return new(params, issued_at:) if params.key?("access_token")

        raise Error.new(code: nil, description: "token response has no access_token", status: Integer(status))
      end

      # Initialize a token from the parameters of a token response
      #
      # @api public
      # @param params [Hash] the token response parameters
      # @param issued_at [Time] when the token was issued, used to compute its expiration
      # @raise [KeyError] if the parameters have no access_token
      # @example
      #   SimpleOAuth::OAuth2::Token.new({"access_token" => "abc", "expires_in" => 3600})
      def initialize(params, issued_at: Time.now)
        @params = params.transform_keys(&:to_s).freeze
        @access_token = @params.fetch("access_token")
        @token_type = @params["token_type"]
        @expires_in = @params["expires_in"]&.then { |seconds| Integer(seconds) }
        @refresh_token = @params["refresh_token"]
        @scope = @params["scope"]
        @expires_at = @expires_in&.then { |seconds| issued_at + seconds }
        freeze
      end

      # The granted scopes
      #
      # @api public
      # @return [Array<String>] the granted scopes
      # @example
      #   token.scopes # => ["tweet.read", "users.read"]
      def scopes
        scope.to_s.split
      end

      # Check whether the access token has expired, or will within a leeway
      #
      # @api public
      # @param leeway [Numeric] seconds before expiration to treat the token as expired
      # @param now [Time] the current time
      # @return [Boolean] true if the token has expired; false if it has not or never expires
      # @example Refresh a token that expires within 30 seconds
      #   token.expired?(leeway: 30)
      def expired?(leeway: 0, now: Time.now)
        return false if expires_at.nil?

        now >= expires_at - leeway
      end
    end
  end
end
