# encoding: utf-8

Gem::Specification.new do |gem|
  gem.name    = 'simple_oauth'
  gem.version = '0.1.9'

  gem.authors     = ["Steve Richert", "Erik Michaels-Ober"]
  gem.email       = ['steve.richert@gmail.com', 'sferik@gmail.com']
  gem.description = 'Simply builds and verifies OAuth headers'
  gem.summary     = gem.description
  gem.homepage    = 'https://github.com/laserlemon/simple_oauth'

  gem.add_development_dependency 'rake'
  gem.add_development_dependency 'rspec', '~> 2.0'
  gem.add_development_dependency 'simplecov'

  gem.files         = `git ls-files`.split($\)
  gem.test_files    = gem.files.grep(/^test\//)
  gem.require_paths = ["lib"]
end
