if RUBY_VERSION >= '1.9'
  require 'simplecov'
  require 'coveralls'

  SimpleCov.formatter = SimpleCov::Formatter::MultiFormatter.new \
    [SimpleCov::Formatter::HTMLFormatter, Coveralls::SimpleCov::Formatter]
  SimpleCov.start do
    add_filter '/spec/'
    add_filter '/.bundle/'
    minimum_coverage(100)
  end
end

require 'simple_oauth'
require 'rspec'

def uri_parser
  @uri_parser ||= URI.const_defined?(:Parser) ? URI::Parser.new : URI
end

RSpec.configure do |config|
  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end

Dir[File.expand_path('../support/**/*.rb', __FILE__)].each { |f| require f }
