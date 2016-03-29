require 'openssl'
require 'uri'
require 'base64'

require 'simple_oauth/signatures/base'
require 'simple_oauth/signatures/plaintext'
require 'simple_oauth/signatures/hmac-sha1'
require 'simple_oauth/signatures/rsa-sha1'

module Signatures
  ENCODERS = {'HMAC-SHA1' => HMAC_SHA1.new,
              'RSA-SHA1'  => RSA_SHA1.new,
              'PLAINTEXT' => Plaintext.new}.freeze
end
