unless ENV['CI']
  require 'simplecov'
  SimpleCov.start do
    add_filter 'spec'
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

Dir[File.expand_path('../support/**/*.rb', __FILE__)].each{|f| require f }
