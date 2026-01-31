module SimpleOAuth
  # Error raised when parsing a malformed OAuth Authorization header
  class ParseError < StandardError; end

  # Error raised when invalid options are passed to Header
  class InvalidOptionsError < StandardError; end
end
