unless ENV['CI']
  require 'simplecov'
  SimpleCov.start
end

require 'simple_oauth'

Dir[File.expand_path('../support/**/*.rb', __FILE__)].each{|f| require f }
