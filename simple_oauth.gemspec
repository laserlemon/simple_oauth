# -*- encoding: utf-8 -*-
require File.expand_path('../lib/simple_oauth', __FILE__)

Gem::Specification.new do |spec|
  spec.add_development_dependency('mocha', '>= 0')
  spec.author = 'Steve Richert'
  spec.description = 'Simply builds and verifies OAuth headers'
  spec.email = 'steve.richert@gmail.com'
  spec.extra_rdoc_files = ['README.rdoc']
  spec.files = `git ls-files`.split("\n")
  spec.homepage = 'http://github.com/laserlemon/simple_oauth'
  spec.name = 'simple_oauth'
  spec.rdoc_options = ['--charset=UTF-8']
  spec.required_ruby_version = '>= 1.8.7'
  spec.summary = 'Simply builds and verifies OAuth headers'
  spec.test_files = `git ls-files -- test/**/*_test.rb`.split("\n")
  spec.version = SimpleOAuth::Version::STRING
end
