$LOAD_PATH.unshift File.expand_path("../lib", __dir__)

require "simplecov"

SimpleCov.start do
  add_filter "/spec/"
  minimum_coverage(100)
end

require "rspec"
require "simple_oauth"

def uri_parser
  @uri_parser ||= URI.const_defined?(:Parser) ? URI::DEFAULT_PARSER : URI
end

RSpec.configure do |config|
  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end

Dir[File.expand_path("support/**/*.rb", __dir__)].each { |f| require f }
