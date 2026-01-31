require "base64"
require "openssl"

module SimpleOAuth
  # Signature computation methods for OAuth 1.0
  #
  # This module provides a registry of signature methods that can be extended
  # with custom implementations. Built-in methods include HMAC-SHA1, HMAC-SHA256,
  # RSA-SHA1, and PLAINTEXT.
  #
  # @api public
  # @example Register a custom signature method
  #   SimpleOAuth::Signature.register("HMAC-SHA512") do |secret, signature_base|
  #     Base64.encode64(OpenSSL::HMAC.digest("SHA512", secret, signature_base)).delete("\n")
  #   end
  #
  # @example Check if a signature method is registered
  #   SimpleOAuth::Signature.registered?("HMAC-SHA1") # => true
  #   SimpleOAuth::Signature.registered?("CUSTOM")    # => false
  module Signature
    # Registry of signature method implementations
    @registry = {}

    class << self
      # Registers a custom signature method
      #
      # @api public
      # @param name [String] the signature method name (e.g., "HMAC-SHA512")
      # @param rsa [Boolean] whether this method uses RSA (raw consumer_secret as key)
      # @yield [secret, signature_base] block that computes the signature
      # @yieldparam secret [String] the signing secret (or PEM key for RSA methods)
      # @yieldparam signature_base [String] the signature base string
      # @yieldreturn [String] the computed signature
      # @return [void]
      # @example
      #   SimpleOAuth::Signature.register("HMAC-SHA512") do |secret, base|
      #     Base64.encode64(OpenSSL::HMAC.digest("SHA512", secret, base)).delete("\n")
      #   end
      def register(name, rsa: false, &block)
        normalized = normalize_name(name)
        @registry[normalized] = {implementation: block, rsa: rsa}
      end

      # Checks if a signature method is registered
      #
      # @api public
      # @param name [String] the signature method name
      # @return [Boolean] true if the method is registered
      # @example
      #   SimpleOAuth::Signature.registered?("HMAC-SHA1") # => true
      def registered?(name)
        @registry.key?(normalize_name(name))
      end

      # Returns list of registered signature method names
      #
      # @api public
      # @return [Array<String>] registered method names
      # @example
      #   SimpleOAuth::Signature.methods # => ["hmac_sha1", "hmac_sha256", "rsa_sha1", "plaintext"]
      def methods
        @registry.keys
      end

      # Checks if a signature method uses RSA (raw key instead of escaped secret)
      #
      # @api public
      # @param name [String] the signature method name
      # @return [Boolean] true if the method uses RSA
      # @example
      #   SimpleOAuth::Signature.rsa?("RSA-SHA1")  # => true
      #   SimpleOAuth::Signature.rsa?("HMAC-SHA1") # => false
      def rsa?(name)
        entry = @registry[normalize_name(name)]
        entry&.fetch(:rsa) || false
      end

      # Computes a signature using the specified method
      #
      # @api public
      # @param name [String] the signature method name
      # @param secret [String] the signing secret
      # @param signature_base [String] the signature base string
      # @return [String] the computed signature
      # @raise [ArgumentError] if the signature method is not registered
      # @example
      #   SimpleOAuth::Signature.sign("HMAC-SHA1", "secret&token", "GET&url&params")
      def sign(name, secret, signature_base)
        normalized = normalize_name(name)
        entry = @registry.fetch(normalized) do
          raise ArgumentError, "Unknown signature method: #{name}. Registered methods: #{@registry.keys.join(", ")}"
        end
        entry.fetch(:implementation).call(secret, signature_base)
      end

      # Unregisters a signature method (useful for testing)
      #
      # @api public
      # @param name [String] the signature method name to remove
      # @return [void]
      # @example
      #   SimpleOAuth::Signature.unregister("HMAC-SHA512")
      def unregister(name)
        @registry.delete(normalize_name(name))
      end

      # Resets the registry to only built-in methods (useful for testing)
      #
      # @api public
      # @return [void]
      # @example
      #   SimpleOAuth::Signature.reset!
      def reset!
        @registry.clear
        register_builtin_methods
      end

      private

      # Normalizes signature method name for registry lookup
      #
      # @api private
      # @param name [String] the signature method name
      # @return [String] normalized name (lowercase, dashes to underscores)
      def normalize_name(name)
        name.to_s.downcase.tr("-", "_")
      end

      # Registers the built-in OAuth signature methods
      #
      # @api private
      # @return [void]
      def register_builtin_methods
        register_hmac_method("HMAC-SHA1", "SHA1")
        register_hmac_method("HMAC-SHA256", "SHA256")
        register_rsa_sha1_method
        register_plaintext_method
      end

      # Registers an HMAC signature method
      #
      # @api private
      # @param name [String] the signature method name
      # @param digest [String] the digest algorithm
      # @return [void]
      def register_hmac_method(name, digest)
        register(name) do |secret, signature_base|
          Base64.encode64(OpenSSL::HMAC.digest(digest, secret, signature_base)).delete("\n")
        end
      end

      # Registers the RSA-SHA1 signature method
      #
      # @api private
      # @return [void]
      def register_rsa_sha1_method
        register("RSA-SHA1", rsa: true) do |private_key_pem, signature_base|
          private_key = OpenSSL::PKey::RSA.new(private_key_pem)
          Base64.encode64(private_key.sign("SHA1", signature_base)).delete("\n")
        end
      end

      # Registers the PLAINTEXT signature method
      #
      # @api private
      # @return [void]
      def register_plaintext_method
        register("PLAINTEXT") { |secret, _signature_base| secret }
      end
    end

    # Initialize built-in methods on load
    register_builtin_methods
  end
end
