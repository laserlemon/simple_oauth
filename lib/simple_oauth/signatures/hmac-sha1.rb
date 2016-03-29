module Signatures
  class HMAC_SHA1
    include Base

  protected
    def digest(secret, base)
      OpenSSL::HMAC.digest(OpenSSL::Digest::SHA1.new, secret, base)
    end
  end
end
