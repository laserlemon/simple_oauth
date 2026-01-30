$LOAD_PATH.unshift File.expand_path("../lib", __dir__)

require "simplecov"

SimpleCov.start do
  enable_coverage :branch
  add_filter "/test/"
  minimum_coverage line: 100, branch: 100
end

require "minitest/autorun"
require "simple_oauth"

# Define a no-op cover method for regular test runs (mutant-minitest defines this when running mutations)
Minitest::Test.define_singleton_method(:cover) { |*| nil } unless Minitest::Test.respond_to?(:cover)

module TestHelpers
  PRIVATE_KEY_PATH = File.expand_path("fixtures/rsa-private-key", __dir__)

  def rsa_private_key
    @rsa_private_key ||= File.read(PRIVATE_KEY_PATH)
  end
end
