# frozen_string_literal: true

require "openssl"

module SimpleOAuth
  class Header
    # Checks of the signature method a received header claims, before it is verified with it
    #
    # @api private
    module Verification
      # The first byte of a key in DER, which encodes every key as an ASN.1 SEQUENCE
      ASN1_SEQUENCE = 0x30

      # The start of the line that opens every key in PEM
      PEM_BOUNDARY = "-----BEGIN"

      private

      # Checks that the header claims a signature method the verifier accepts
      #
      # @api private
      # @param verifying [Hash] the header's options merged with the verifier's secrets
      # @param expected [String, nil] the signature method the verifier expects, if it names one
      # @return [Boolean] true if the claimed method is the expected one, or fits the key
      # @raise [ArgumentError] if the expected signature method is not registered
      def signature_method_acceptable?(verifying, expected)
        claimed = options[:signature_method].to_s
        return expected_signature_method?(claimed, expected) if expected

        warn("SimpleOAuth::Header#valid? without a signature_method is deprecated. " \
             "Name the method to verify with, such as signature_method: \"HMAC-SHA1\"", category: :deprecated)
        key = verifying[:consumer_secret].to_s
        Signature.registered?(claimed) && !PLAINTEXT_SIGNATURE_METHOD.casecmp(claimed).eql?(0) &&
          (Signature.rsa?(claimed) ? key_encoded?(key) : !rsa_key?(key))
      end

      # Checks that the header claims the signature method the verifier names
      #
      # Signature method names are compared without regard to ASCII case, as the registry looks
      # them up, and without allocating. A header that claims the expected method needs no other
      # check here, since Signature.verify raises for a method that is not registered.
      #
      # @api private
      # @param claimed [String] the signature method the header claims
      # @param expected [String] the signature method the verifier expects
      # @return [Boolean] true if the header claims the expected method
      # @raise [ArgumentError] if the expected signature method is not registered
      def expected_signature_method?(claimed, expected)
        return true if claimed.casecmp(expected).eql?(0)
        raise ArgumentError, "Unknown signature method: #{expected}" unless Signature.registered?(expected)

        false
      end

      # Checks whether a verifying key is encoded as a key could be
      #
      # Only a key in PEM, which always holds a "-----BEGIN" line, or in DER, which always starts with
      # the byte of an ASN.1 SEQUENCE, can be an RSA key, as those are the encodings OpenSSL decodes.
      # Any other secret need not be parsed, which matters since a parse that fails is far slower
      # than verifying a signature.
      #
      # @api private
      # @param key [String] the consumer_secret the verifier gave
      # @return [Boolean] true if the key is in PEM or could be in DER
      def key_encoded?(key)
        key.getbyte(0).eql?(ASN1_SEQUENCE) || key.include?(PEM_BOUNDARY)
      end

      # Checks whether a verifying key is an RSA key
      #
      # @api private
      # @param key [String] the consumer_secret the verifier gave
      # @return [Boolean] true if the key parses as an RSA key
      def rsa_key?(key)
        return false unless key_encoded?(key)

        OpenSSL::PKey::RSA.new(key)
        true
      rescue OpenSSL::PKey::PKeyError
        false
      end
    end
  end
end
