# frozen_string_literal: true

# OAuth percent-encoding, which signing runs on every key and value

duel "encode: a short unreserved value" do
  SimpleOAuth::Header.escape("dpf43f3p2l4k3l03")
end

duel "encode: a status with reserved characters" do
  SimpleOAuth::Header.escape("Hello Ladies + Gentlemen, a signed OAuth request! (50% off) #ruby")
end

duel "encode: 1 KB of multibyte text" do
  once { @text = "Ünïcödé テキスト 😀 " * 50 }
  SimpleOAuth::Header.escape(@text)
end

duel "decode: a percent-encoded status" do
  SimpleOAuth::Header.unescape("Hello%20Ladies%20%2B%20Gentlemen%2C%20a%20signed%20OAuth%20request%21")
end
