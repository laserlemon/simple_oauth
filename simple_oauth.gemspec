Gem::Specification.new do |spec|
  spec.add_development_dependency 'bundler', '~> 1.0'
  spec.name    = 'simple_oauth'
  spec.version = '0.2.0'

  spec.authors     = ['Steve Richert', 'Erik Michaels-Ober']
  spec.email       = %w(steve.richert@gmail.com sferik@gmail.com)
  spec.description = 'Simply builds and verifies OAuth headers'
  spec.summary     = spec.description
  spec.homepage    = 'https://github.com/laserlemon/simple_oauth'
  spec.licenses    = %w(MIT)

  spec.files         = `git ls-files`.split($OUTPUT_RECORD_SEPARATOR)
  spec.test_files    = spec.files.grep(/^test\//)
  spec.require_paths = %w(lib)
end
