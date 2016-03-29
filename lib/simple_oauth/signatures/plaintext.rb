module Signatures
  class Plaintext
    include Base

    def create(consumer_secret, token_secret, _base)
      @consumer_secret, @token_secret = consumer_secret, token_secret
      secret
    end
  end
end
