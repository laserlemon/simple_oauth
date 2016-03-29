module Signatures
  class RSA_SHA1
    include Base

  protected

    def digest(_secret, base)
      private_key.sign(OpenSSL::Digest::SHA1.new, base)
    end

    def private_key
      OpenSSL::PKey::RSA.new(@consumer_secret)
    end
  end
end
