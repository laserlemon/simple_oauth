# frozen_string_literal: true

require_relative "duel_helper"

# Reading OAuth credentials back from a request, which a server does
# once per request it receives

duel "parse: an Authorization header" do
  once do
    @header = SimpleOAuth::Header.new(:post, DuelHelper::URL, DuelHelper::STATUS_PARAMS,
      DuelHelper.oauth(realm: "Example", callback: "https://printer.example.com/ready")).to_s
  end
  SimpleOAuth::Header.parse(@header)
end

duel "parse: credentials from a form body" do
  once do
    header = SimpleOAuth::Header.new(:post, DuelHelper::URL, DuelHelper::STATUS_PARAMS, DuelHelper.oauth)
    oauth = header.signed_attributes
    @body = URI.encode_www_form(DuelHelper::STATUS_PARAMS.merge(oauth))
  end
  SimpleOAuth::Header.parse_form_body(@body)
end
