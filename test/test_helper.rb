$LOAD_PATH.unshift File.expand_path("../lib", __dir__)

require "simplecov"

SimpleCov.start do
  add_filter "/test/"
  minimum_coverage(100)
end

require "minitest/autorun"
require "simple_oauth"

module TestHelpers
  PRIVATE_KEY_PATH = File.expand_path("fixtures/rsa-private-key", __dir__)

  def rsa_private_key
    @rsa_private_key ||= File.read(PRIVATE_KEY_PATH)
  end
end
