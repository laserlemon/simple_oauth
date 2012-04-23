unless ENV['CI']
  require 'simplecov'
  SimpleCov.start
end

require 'bundler'
Bundler.setup
require 'test/unit'
require 'mocha'
require 'simple_oauth'
