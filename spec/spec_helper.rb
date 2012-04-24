unless ENV['CI']
  require 'simplecov'
  SimpleCov.start do
    add_filter 'spec'
  end
end

require 'simple_oauth'

Dir[File.expand_path('../support/**/*.rb', __FILE__)].each{|f| require f }
