require "base64"
require "openssl"

module SimpleOAuth
  # Signature computation methods for OAuth 1.0
  #
  # @api private
  module Signature
    # Computes HMAC-SHA1 signature
    #
    # @api private
    # @param secret [String] the signing secret
    # @param signature_base [String] the signature base string
    # @return [String] HMAC-SHA1 signature
    def self.hmac_sha1(secret, signature_base)
      Base64.encode64(OpenSSL::HMAC.digest("SHA1", secret, signature_base)).delete("\n")
    end

    # Computes HMAC-SHA256 signature
    #
    # @api private
    # @param secret [String] the signing secret
    # @param signature_base [String] the signature base string
    # @return [String] HMAC-SHA256 signature
    def self.hmac_sha256(secret, signature_base)
      Base64.encode64(OpenSSL::HMAC.digest("SHA256", secret, signature_base)).delete("\n")
    end

    # Computes RSA-SHA1 signature using private key
    #
    # @api private
    # @param private_key_pem [String] the PEM-encoded RSA private key
    # @param signature_base [String] the signature base string
    # @return [String] RSA-SHA1 signature
    def self.rsa_sha1(private_key_pem, signature_base)
      private_key = OpenSSL::PKey::RSA.new(private_key_pem)
      Base64.encode64(private_key.sign("SHA1", signature_base)).delete("\n")
    end

    # Returns PLAINTEXT signature (escaped secrets joined by &)
    #
    # @api private
    # @param secret [String] the signing secret
    # @return [String] PLAINTEXT signature
    def self.plaintext(secret, _signature_base = nil)
      secret
    end
  end
end
