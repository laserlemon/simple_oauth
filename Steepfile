# frozen_string_literal: true

D = Steep::Diagnostic

target :lib do
  signature "sig"

  check "lib"

  library "openssl"
  library "uri"
  library "securerandom"
  library "json"

  configure_code_diagnostics(D::Ruby.strict) do |hash|
    # Allow FallbackAny warnings for variables in ensure blocks
    hash[D::Ruby::FallbackAny] = :hint
  end
end
