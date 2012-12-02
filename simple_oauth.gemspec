# encoding: utf-8

Gem::Specification.new do |spec|
  spec.name    = 'simple_oauth'
  spec.version = '0.2.0'

  spec.authors     = ["Steve Richert", "Erik Michaels-Ober"]
  spec.email       = ['steve.richert@gmail.com', 'sferik@gmail.com']
  spec.description = 'Simply builds and verifies OAuth headers'
  spec.summary     = spec.description
  spec.homepage    = 'https://github.com/laserlemon/simple_oauth'
  spec.licenses    = ['MIT']

  spec.add_development_dependency 'rake'
  spec.add_development_dependency 'rspec', '>= 2'
  spec.add_development_dependency 'simplecov'

  spec.files         = `git ls-files`.split($\)
  spec.test_files    = spec.files.grep(/^test\//)
  spec.require_paths = ["lib"]
end
