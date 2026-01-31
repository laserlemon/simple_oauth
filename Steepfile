D = Steep::Diagnostic

target :lib do
  signature "sig"

  check "lib"

  library "base64"
  library "openssl"
  library "uri"
  library "cgi"
  library "securerandom"

  configure_code_diagnostics(D::Ruby.strict) do |hash|
    # Allow FallbackAny warnings for variables in ensure blocks
    hash[D::Ruby::FallbackAny] = :hint
  end
end
