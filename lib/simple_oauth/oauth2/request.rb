module SimpleOAuth
  module OAuth2
    # An HTTP request to an OAuth 2.0 endpoint, built but not sent
    #
    # @api public
    # @example Send a request with Net::HTTP
    #   response = Net::HTTP.post(URI(request.url), request.body, request.headers)
    class Request
      # The HTTP method
      #
      # @api public
      # @return [String] the HTTP method
      # @example
      #   request.method # => "POST"
      attr_reader :method

      # The endpoint URL
      #
      # @api public
      # @return [String] the URL
      # @example
      #   request.url # => "https://example.com/token"
      attr_reader :url

      # The request headers
      #
      # @api public
      # @return [Hash{String => String}] the headers
      # @example
      #   request.headers["Content-Type"] # => "application/x-www-form-urlencoded"
      attr_reader :headers

      # The form-encoded request body
      #
      # @api public
      # @return [String] the body
      # @example
      #   request.body # => "grant_type=refresh_token&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA"
      attr_reader :body

      # Initialize a new request
      #
      # @api public
      # @param method [String] the HTTP method
      # @param url [String] the endpoint URL
      # @param headers [Hash{String => String}] the request headers
      # @param body [String] the form-encoded request body
      # @example
      #   SimpleOAuth::OAuth2::Request.new(method: "POST", url: "https://example.com/token", headers: {}, body: "")
      def initialize(method:, url:, headers:, body:)
        @method = method
        @url = url
        @headers = headers.dup.freeze
        @body = body
        freeze
      end
    end
  end
end
