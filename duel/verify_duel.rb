# frozen_string_literal: true

require_relative "duel_helper"

# Verifying a signed request, which a server does once per request: parse
# the header, rebuild the signature base string, and compare signatures

duel "verify: HMAC-SHA1 POST, a status update" do
  once { @header = SimpleOAuth::Header.new(:post, DuelHelper::URL, DuelHelper::STATUS_PARAMS, DuelHelper.oauth).to_s }
  SimpleOAuth::Header.new(:post, DuelHelper::URL, DuelHelper::STATUS_PARAMS, @header).valid?(DuelHelper::SECRETS) ||
    raise("the signature didn't verify")
end

duel "verify: RSA-SHA1 with a public key" do
  once do
    key = DuelHelper.rsa_private_key
    options = DuelHelper.oauth(signature_method: "RSA-SHA1", consumer_secret: key)
    @header = SimpleOAuth::Header.new(:post, DuelHelper::URL, DuelHelper::STATUS_PARAMS, options).to_s
    @public_key = OpenSSL::PKey::RSA.new(key).public_key.to_pem
  end
  header = SimpleOAuth::Header.new(:post, DuelHelper::URL, DuelHelper::STATUS_PARAMS, @header)
  header.valid?(consumer_secret: @public_key) || raise("the signature didn't verify")
end

duel "verify: HMAC-SHA1 with a 1 KB JSON body" do
  once do
    @body = %({"text": "#{"a" * 1000}"})
    @header = SimpleOAuth::Header.new(:post, DuelHelper::URL, {}, DuelHelper.oauth, @body).to_s
  end
  SimpleOAuth::Header.new(:post, DuelHelper::URL, {}, @header, @body).valid?(DuelHelper::SECRETS) ||
    raise("the signature didn't verify")
end
