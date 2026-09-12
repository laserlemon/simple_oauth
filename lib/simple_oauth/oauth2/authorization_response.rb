# frozen_string_literal: true

require "openssl"
require "uri"
require_relative "error"

module SimpleOAuth
  module OAuth2
    # The response an authorization server returns to a client's redirect URI
    #
    # Parsing one makes the checks a client owes its own request before it sends the code
    # anywhere: that the server reported no error, that the response answers the request this
    # client made, and that it came from the authorization server the client expected.
    #
    # @api public
    # @example Read the code out of a callback
    #   response = SimpleOAuth::OAuth2::AuthorizationResponse.parse(request.query_string,
    #     state: session[:state])
    #   token_request = client.authorization_code_request(code: response.code,
    #     redirect_uri: "https://app.example/cb", code_verifier: session[:verifier])
    #
    # @see https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2 RFC 6749 - Authorization Response
    # @see https://www.rfc-editor.org/rfc/rfc9207 RFC 9207 - Authorization Server Issuer Identification
    class AuthorizationResponse
      # The description of a response whose state is not the one the request sent
      STATE_MISMATCH = "The authorization response answers a different request"
      # The description of a response from an authorization server other than the expected one
      ISSUER_MISMATCH = "The authorization response is from a different authorization server"
      # The description of a response carrying neither a code nor an error
      NO_CODE = "The authorization response has no code"
      # The description of a response that repeats a parameter, which RFC 6749 Section 3.1 forbids
      DUPLICATE_PARAMETER = "The authorization response repeats a parameter"

      # The authorization code, to exchange for a token
      #
      # @api public
      # @return [String] the authorization code
      # @example
      #   response.code # => "SplxlOBeZQQYbYS6WxSbIA"
      attr_reader :code

      # The state the authorization server returned
      #
      # @api public
      # @return [String, nil] the state
      # @example
      #   response.state # => "xyz"
      attr_reader :state

      # The issuer the authorization server identified itself with (RFC 9207)
      #
      # @api public
      # @return [String, nil] the issuer
      # @example
      #   response.issuer # => "https://server.example.com"
      attr_reader :issuer

      # Every parameter of the authorization response
      #
      # @api public
      # @return [Hash{String => String}] the parameters
      # @example
      #   response.params["code"] # => "SplxlOBeZQQYbYS6WxSbIA"
      attr_reader :params

      # Parse an authorization response, raising unless the client can trust and use it
      #
      # @api public
      # @param query [String, Hash, nil] the query string of the redirect, or its parsed parameters
      # @param state [String, nil] the state the authorization URL sent, which the response must
      #   carry; nil to make no such check, for a request that sent none
      # @param issuer [String, nil] the issuer the server must identify itself with; nil to make
      #   no such check
      # @return [AuthorizationResponse] the response
      # @raise [Error] if the server reported an error, or the response cannot be trusted
      # @example
      #   SimpleOAuth::OAuth2::AuthorizationResponse.parse("code=abc&state=xyz", state: "xyz")
      def self.parse(query, state: nil, issuer: nil)
        params = parameters(query)
        raise reported_error(params) if params.key?("error")

        reason = mismatch_reason(params, state, issuer)
        raise Error.new(code: nil, description: reason) if reason

        new(params)
      end

      # The parameters of an authorization response
      #
      # @api private
      # @param query [String, Hash, nil] the query string of the redirect, or its parsed parameters
      # @return [Hash{String => String}] the parameters
      # @raise [Error] if a parameter is repeated, which RFC 6749 Section 3.1 forbids
      # @example
      #   SimpleOAuth::OAuth2::AuthorizationResponse.parameters("code=abc") # => {"code" => "abc"}
      def self.parameters(query)
        return query.transform_keys(&:to_s) if query.is_a?(Hash)

        pairs = URI.decode_www_form(query.to_s)
        raise Error.new(code: nil, description: DUPLICATE_PARAMETER) if pairs.length > pairs.uniq(&:first).length

        pairs.to_h
      end

      # The error the authorization server reported (RFC 6749 Section 4.1.2.1)
      #
      # @api private
      # @param params [Hash] the response parameters
      # @return [Error] the error
      # @example
      #   SimpleOAuth::OAuth2::AuthorizationResponse.reported_error({"error" => "access_denied"})
      def self.reported_error(params)
        Error.new(code: params["error"], description: params["error_description"], uri: params["error_uri"])
      end

      # The reason a response cannot be trusted or used, if there is one
      #
      # @api private
      # @param params [Hash] the response parameters
      # @param state [String, nil] the state the request sent
      # @param issuer [String, nil] the expected issuer
      # @return [String, nil] the reason, or nil if the response is usable
      # @example
      #   SimpleOAuth::OAuth2::AuthorizationResponse.mismatch_reason({"code" => "a"}, nil, nil) # => nil
      def self.mismatch_reason(params, state, issuer)
        return STATE_MISMATCH unless matches?(state, params["state"])
        return ISSUER_MISMATCH unless matches?(issuer, params["iss"])

        NO_CODE if params["code"].to_s.empty?
      end

      # Whether the response carries what the client expected, in constant time
      #
      # @api private
      # @param expected [String, nil] what the client expects, or nil to expect anything
      # @param actual [String, nil] what the response carried
      # @return [Boolean] true if the response is acceptable
      # @example
      #   SimpleOAuth::OAuth2::AuthorizationResponse.matches?("xyz", "xyz") # => true
      def self.matches?(expected, actual)
        return true if expected.nil?

        !actual.nil? && OpenSSL.secure_compare(expected, actual)
      end

      # Initialize a response from the parameters of an authorization response
      #
      # @api public
      # @param params [Hash] the response parameters
      # @raise [KeyError] if the parameters have no code
      # @example
      #   SimpleOAuth::OAuth2::AuthorizationResponse.new({"code" => "abc", "state" => "xyz"})
      def initialize(params)
        @params = params.transform_keys(&:to_s).freeze
        @code = @params.fetch("code")
        @state = @params["state"]
        @issuer = @params["iss"]
        freeze
      end
    end
  end
end
