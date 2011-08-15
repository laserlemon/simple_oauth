# encoding: utf-8
require File.expand_path('../lib/simple_oauth/version', __FILE__)

Gem::Specification.new do |gem|
  gem.add_development_dependency 'minitest', '~> 2.3'
  gem.add_development_dependency 'mocha', '~> 0.9'
  gem.add_development_dependency 'rake', '~> 0.9'
  gem.add_development_dependency 'simplecov', '~> 0.4'
  gem.add_development_dependency 'yard', '~> 0.7'
  gem.authors = ["Steve Richert", "Erik Michaels-Ober"]
  gem.description = 'Simply builds and verifies OAuth headers'
  gem.email = ['steve.richert@gmail.com', 'sferik@gmail.com']
  gem.files = `git ls-files`.split("\n")
  gem.homepage = 'http://github.com/laserlemon/simple_oauth'
  gem.name = 'simple_oauth'
  gem.required_rubygems_version = Gem::Requirement.new('>= 1.3.6')
  gem.summary = gem.description
  gem.test_files = `git ls-files -- test/**/*_test.rb`.split("\n")
  gem.version = SimpleOAuth::Version::STRING
end
