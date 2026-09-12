# frozen_string_literal: true

module SimpleOAuth
  # The base of every error the library raises, so one rescue catches them all
  class Error < StandardError; end

  # Error raised when parsing a malformed OAuth Authorization header
  class ParseError < Error; end

  # Error raised when invalid options are passed to Header
  class InvalidOptionsError < Error; end
end
