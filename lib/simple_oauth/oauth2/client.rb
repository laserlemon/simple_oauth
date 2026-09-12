# frozen_string_literal: true

require "uri"
require_relative "request"

module SimpleOAuth
  module OAuth2
    # An OAuth 2.0 client that builds authorization URLs and endpoint requests
    #
    # A client with a secret is confidential and authenticates to the token and revocation endpoints
    # with HTTP Basic (client_secret_basic) or in the request body (client_secret_post). A client without
    # a secret is public and identifies itself with its client_id alone.
    #
    # @api public
    # @example Build the requests of an authorization code flow with PKCE
    #   client = SimpleOAuth::OAuth2::Client.new(client_id: "id",
    #     authorization_endpoint: "https://example.com/authorize", token_endpoint: "https://example.com/token")
    #   pkce = SimpleOAuth::OAuth2::PKCE.generate
    #   url = client.authorization_url(redirect_uri: "https://app.example/cb", state: "xyz", pkce: pkce)
    #   request = client.authorization_code_request(code: params[:code], redirect_uri: "https://app.example/cb",
    #     code_verifier: pkce.verifier)
    class Client
      # Client authentication methods for confidential clients (RFC 6749 Section 2.3.1)
      AUTH_METHODS = %i[client_secret_basic client_secret_post].freeze
      # The content type of every request body
      FORM_CONTENT_TYPE = "application/x-www-form-urlencoded"
      # The error message for a state that is given but empty
      EMPTY_STATE = "The state must not be empty"
      # The error message for an authorization request that nothing ties to its response
      UNPROTECTED = "Pass a pkce, or a state, so that the authorization response can be tied to this request"

      # The client identifier
      #
      # @api public
      # @return [String] the client identifier
      # @example
      #   client.client_id # => "s6BhdRkqt3"
      attr_reader :client_id

      # The client secret, or nil for a public client
      #
      # @api public
      # @return [String, nil] the client secret
      # @example
      #   client.client_secret # => "gX1fBat3bV"
      attr_reader :client_secret

      # The authorization endpoint URL
      #
      # @api public
      # @return [String, nil] the authorization endpoint
      # @example
      #   client.authorization_endpoint # => "https://example.com/authorize"
      attr_reader :authorization_endpoint

      # The token endpoint URL
      #
      # @api public
      # @return [String, nil] the token endpoint
      # @example
      #   client.token_endpoint # => "https://example.com/token"
      attr_reader :token_endpoint

      # The revocation endpoint URL
      #
      # @api public
      # @return [String, nil] the revocation endpoint
      # @example
      #   client.revocation_endpoint # => "https://example.com/revoke"
      attr_reader :revocation_endpoint

      # How a confidential client authenticates with its secret
      #
      # @api public
      # @return [Symbol] the authentication method
      # @example
      #   client.auth_method # => :client_secret_basic
      attr_reader :auth_method

      # Initialize a new client
      #
      # @api public
      # @param client_id [String] the client identifier
      # @param client_secret [String, nil] the client secret, or nil for a public client; an empty
      #   secret is no secret, so a client given one is public
      # @param authorization_endpoint [String, nil] the authorization endpoint URL
      # @param token_endpoint [String, nil] the token endpoint URL
      # @param revocation_endpoint [String, nil] the revocation endpoint URL
      # @param auth_method [Symbol] how a confidential client authenticates: client_secret_basic or client_secret_post
      # @raise [ArgumentError] if the authentication method is unknown
      # @example A confidential client
      #   SimpleOAuth::OAuth2::Client.new(client_id: "s6BhdRkqt3", client_secret: "gX1fBat3bV",
      #     token_endpoint: "https://example.com/token")
      def initialize(client_id:, client_secret: nil, authorization_endpoint: nil, token_endpoint: nil,
        revocation_endpoint: nil, auth_method: :client_secret_basic)
        raise ArgumentError, "Unknown auth_method: #{auth_method.inspect}" unless AUTH_METHODS.include?(auth_method)

        @client_id = client_id
        @client_secret = client_secret
        @authorization_endpoint = authorization_endpoint
        @token_endpoint = token_endpoint
        @revocation_endpoint = revocation_endpoint
        @auth_method = auth_method
        freeze
      end

      # Check whether the client is public, meaning it has no secret
      #
      # A secret that is empty is no secret, so a client holding one cannot authenticate
      # with it and identifies itself with its client_id alone.
      #
      # @api public
      # @return [Boolean] true if the client has no secret
      # @example
      #   client.public? # => false
      def public?
        client_secret.to_s.empty?
      end

      # Build the URL where the user authorizes the client (RFC 6749 Section 4.1.1)
      #
      # The pkce is named rather than defaulted because only the caller can keep the verifier
      # to send with the code. OAuth 2.1 asks every client for one, so pass `pkce: nil` to
      # leave it out, for an authorization server that rejects the challenge parameters.
      #
      # A state is what OAuth 2.0 ties the response to the request with. A PKCE challenge does
      # that too, so with one the state is free to carry application state, or to be left out.
      #
      # @api public
      # @param redirect_uri [String] where the authorization server returns the user
      # @param pkce [PKCE, nil] the PKCE challenge to send, or nil to send none
      # @param state [String, nil] an unguessable value the authorization server returns with
      #   the code, which {AuthorizationResponse.parse} checks
      # @param scope [String, Array<String>, nil] the requested scope
      # @param params [Hash] additional query parameters, which override the ones the client
      #   sends itself, whether their keys are Strings or Symbols
      # @return [String] the authorization URL
      # @raise [ArgumentError] if the state is given but empty, if neither a pkce nor a state
      #   is given, or if the client has no authorization endpoint
      # @example
      #   client.authorization_url(redirect_uri: "https://app.example/cb", state: "xyz",
      #     scope: %w[tweet.read users.read], pkce: SimpleOAuth::OAuth2::PKCE.generate)
      def authorization_url(redirect_uri:, pkce:, state: nil, scope: nil, params: {})
        validate_protection!(pkce, state)
        url = endpoint(authorization_endpoint, :authorization_endpoint)
        query = {response_type: "code", client_id:, redirect_uri:, scope: scope_value(scope), state:,
                 code_challenge: pkce&.challenge, code_challenge_method: pkce&.challenge_method}
        # Symbolize the caller's keys so that a String key overrides rather than repeating a parameter
        query = query.merge(params.transform_keys(&:to_sym)).compact
        "#{url}#{url.include?("?") ? "&" : "?"}#{URI.encode_www_form(query)}"
      end

      # Build the request that exchanges an authorization code for a token
      #
      # @api public
      # @param code [String] the authorization code
      # @param redirect_uri [String] the redirect URI sent in the authorization URL
      # @param code_verifier [String, nil] the PKCE verifier, if the authorization URL sent a challenge
      # @param params [Hash] additional form parameters, which override the ones the client sends itself
      # @return [Request] the token request
      # @raise [ArgumentError] if the client has no token endpoint
      # @example
      #   client.authorization_code_request(code: "SplxlOBeZQQYbYS6WxSbIA", redirect_uri: "https://app.example/cb",
      #     code_verifier: pkce.verifier)
      def authorization_code_request(code:, redirect_uri:, code_verifier: nil, params: {})
        token_request({grant_type: "authorization_code", code:, redirect_uri:, code_verifier:}, params)
      end

      # Build the request that exchanges a refresh token for a new token
      #
      # @api public
      # @param refresh_token [String] the refresh token
      # @param scope [String, Array<String>, nil] a narrower scope to request
      # @param params [Hash] additional form parameters, which override the ones the client sends itself
      # @return [Request] the token request
      # @raise [ArgumentError] if the client has no token endpoint
      # @example
      #   client.refresh_token_request(refresh_token: "tGzv3JOkF0XG5Qx2TlKWIA")
      def refresh_token_request(refresh_token:, scope: nil, params: {})
        token_request({grant_type: "refresh_token", refresh_token:, scope: scope_value(scope)}, params)
      end

      # Build the request for a token that acts as the client itself
      #
      # @api public
      # @param scope [String, Array<String>, nil] the requested scope
      # @param params [Hash] additional form parameters, which override the ones the client sends itself
      # @return [Request] the token request
      # @raise [ArgumentError] if the client is public or has no token endpoint
      # @example
      #   client.client_credentials_request
      def client_credentials_request(scope: nil, params: {})
        raise ArgumentError, "The client credentials grant requires a client secret" if public?

        token_request({grant_type: "client_credentials", scope: scope_value(scope)}, params)
      end

      # Build the request that revokes an access or refresh token (RFC 7009 Section 2.1)
      #
      # @api public
      # @param token [String] the token to revoke
      # @param token_type_hint [String, nil] access_token or refresh_token
      # @param params [Hash] additional form parameters, which override the ones the client sends itself
      # @return [Request] the revocation request
      # @raise [ArgumentError] if the client has no revocation endpoint
      # @example
      #   client.revocation_request(token: "45ghiukldjahdnhzdauz", token_type_hint: "refresh_token")
      def revocation_request(token:, token_type_hint: nil, params: {})
        form_request(endpoint(revocation_endpoint, :revocation_endpoint), {token:, token_type_hint:}, params)
      end

      private

      # Checks that something ties the authorization response to the request
      #
      # @api private
      # @param pkce [PKCE, nil] the PKCE challenge to send, or nil to send none
      # @param state [String, nil] the state to send, or nil to send none
      # @return [void]
      # @raise [ArgumentError] if the state is given but empty, or neither is given
      def validate_protection!(pkce, state)
        raise ArgumentError, EMPTY_STATE if !state.nil? && state.empty?
        raise ArgumentError, UNPROTECTED if pkce.nil? && state.nil?
      end

      # Build a request to the token endpoint
      #
      # @api private
      # @param params [Hash] the form parameters
      # @param extra [Hash] the caller's own form parameters
      # @return [Request] the request
      def token_request(params, extra)
        form_request(endpoint(token_endpoint, :token_endpoint), params, extra)
      end

      # Build an authenticated form POST
      #
      # The caller's own parameters are merged last, so that they can carry an extension such
      # as the resource of RFC 8707, and can replace anything the client would send itself.
      #
      # @api private
      # @param url [String] the endpoint URL
      # @param params [Hash] the form parameters
      # @param extra [Hash] the caller's own form parameters
      # @return [Request] the request
      def form_request(url, params, extra)
        headers, params = authenticated(params)
        # Symbolize the caller's keys so that a String key overrides rather than repeating a parameter
        body = params.merge(extra.transform_keys(&:to_sym)).compact
        Request.new(method: "POST", url:, headers:, body: URI.encode_www_form(body))
      end

      # The headers and form parameters that carry the client's credentials
      #
      # A confidential client authenticates with HTTP Basic or in the body, and a public client
      # identifies itself with its client_id alone (RFC 6749 Section 2.3.1).
      #
      # @api private
      # @param params [Hash] the form parameters
      # @return [Array(Hash, Hash)] the headers and the form parameters
      def authenticated(params)
        headers = {"Content-Type" => FORM_CONTENT_TYPE, "Accept" => "application/json"}
        secret = client_secret unless public?
        return [headers, params.merge(client_id:)] if secret.nil?
        return [headers, params.merge(client_id:, client_secret: secret)] if auth_method.eql?(:client_secret_post)

        [headers.merge("Authorization" => basic_authorization(secret)), params]
      end

      # The HTTP Basic credentials, form-encoded first per RFC 6749 Section 2.3.1
      #
      # @api private
      # @param secret [String] the client secret
      # @return [String] the Authorization header value
      def basic_authorization(secret)
        credentials = [client_id, secret].map { |value| URI.encode_www_form_component(value) }.join(":")
        # "m0" is Base64 with no line breaks
        "Basic #{[credentials].pack("m0")}"
      end

      # Join a list of scopes with spaces
      #
      # RFC 6749 Appendix A.4 defines a scope as one or more characters, so an empty
      # scope is omitted rather than sent as an empty parameter.
      #
      # @api private
      # @param scope [String, Array<String>, nil] the scope
      # @return [String, nil] the space-delimited scope, or nil if there is none
      def scope_value(scope)
        # Array#join flattens, so a String and an Array of Strings both join correctly, and nil joins to ""
        value = [scope].join(" ")
        value unless value.empty?
      end

      # An endpoint URL, which must be configured
      #
      # @api private
      # @param url [String, nil] the endpoint URL
      # @param name [Symbol] the endpoint name for the error message
      # @return [String] the endpoint URL
      # @raise [ArgumentError] if the endpoint is not configured
      def endpoint(url, name)
        url || raise(ArgumentError, "The client has no #{name}")
      end
    end
  end
end
