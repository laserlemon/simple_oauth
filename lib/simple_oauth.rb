require_relative "simple_oauth/header"
require_relative "simple_oauth/version"

module SimpleOAuth
  # Error raised when parsing a malformed OAuth Authorization header
  class ParseError < StandardError; end
end
