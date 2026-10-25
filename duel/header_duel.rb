# frozen_string_literal: true

require_relative "duel_helper"

# Building a signed Authorization header, which a client does once per
# request: percent-encoding, the signature base string, and the signature

duel "header: HMAC-SHA1 GET, no parameters" do
  SimpleOAuth::Header.new(:get, DuelHelper::URL, {}, DuelHelper.oauth).to_s
end

duel "header: HMAC-SHA1 POST, a status update" do
  SimpleOAuth::Header.new(:post, DuelHelper::URL, DuelHelper::STATUS_PARAMS, DuelHelper.oauth).to_s
end

duel "header: HMAC-SHA1 GET, query and realm" do
  url = "https://api.example.com/1.1/search/tweets.json?q=%23ruby%20oauth&count=100&result_type=recent"
  SimpleOAuth::Header.new(:get, url, {}, DuelHelper.oauth(realm: "Example")).to_s
end

duel "header: HMAC-SHA1 POST, 25 long parameters" do
  once { @params = DuelHelper.many_params(25) }
  SimpleOAuth::Header.new(:post, DuelHelper::URL, @params, DuelHelper.oauth).to_s
end

duel "header: HMAC-SHA256 POST, a status update" do
  SimpleOAuth::Header.new(:post, DuelHelper::URL, DuelHelper::STATUS_PARAMS,
    DuelHelper.oauth(signature_method: "HMAC-SHA256")).to_s
end

duel "header: PLAINTEXT GET" do
  SimpleOAuth::Header.new(:get, DuelHelper::URL, {}, DuelHelper.oauth(signature_method: "PLAINTEXT")).to_s
end

duel "header: RSA-SHA1 POST, a status update" do
  once { @options = DuelHelper.oauth(signature_method: "RSA-SHA1", consumer_secret: DuelHelper.rsa_private_key) }
  SimpleOAuth::Header.new(:post, DuelHelper::URL, DuelHelper::STATUS_PARAMS, @options).to_s
end

duel "header: body hash of a 1 KB JSON body" do
  once { @body = %({"text": "#{"a" * 1000}"}) }
  SimpleOAuth::Header.new(:post, DuelHelper::URL, {}, DuelHelper.oauth, @body).to_s
end

duel "header: body hash of a 1 MB upload" do
  once { @body = Random.new(42).bytes(1024 * 1024) }
  SimpleOAuth::Header.new(:post, DuelHelper::URL, {}, DuelHelper.oauth, @body).to_s
end

duel "header: from a form-encoded Net::HTTP request" do
  once do
    @request = Net::HTTP::Post.new(URI("#{DuelHelper::URL}?trim_user=true"))
    @request.set_form_data(DuelHelper::STATUS_PARAMS)
  end
  SimpleOAuth::Header.from_request(@request, DuelHelper.oauth).to_s
end
