require './lib/simple_oauth'
require 'rubygems'
require 'rake'
require 'rake/testtask'
require 'rake/rdoctask'

begin
  require 'jeweler'
  Jeweler::Tasks.new do |gem|
    gem.name = 'simple_oauth'
    gem.version = SimpleOAuth::Version::STRING
    gem.summary = 'Simply builds and verifies OAuth headers'
    gem.description = 'Simply builds and verifies OAuth headers'
    gem.email = 'steve.richert@gmail.com'
    gem.homepage = 'http://github.com/laserlemon/simple_oauth'
    gem.authors = ['Steve Richert']
    gem.add_development_dependency 'mocha'
    # gem is a Gem::Specification... see http://www.rubygems.org/read/chapter/20 for additional settings
  end
  Jeweler::GemcutterTasks.new
rescue LoadError
  puts 'Jeweler is not available. Install it with: gem install jeweler'
end

Rake::TestTask.new do |test|
  test.libs << 'lib' << 'test'
  test.pattern = 'test/**/*_test.rb'
  test.verbose = true
end

task :test => :check_dependencies

task :default => :test

begin
  require 'rcov/rcovtask'
  Rcov::RcovTask.new do |rcov|
    rcov.libs << 'lib' << 'test'
    rcov.pattern = 'test/**/*_test.rb'
    rcov.verbose = true
    rcov.rcov_opts << '--exclude "gems/*"'
  end
rescue LoadError
  task :rcov do
    abort 'RCov is not available. Install it with: gem install rcov'
  end
end

Rake::RDocTask.new do |rdoc|
  version = SimpleOAuth::Version::STRING
  rdoc.rdoc_dir = 'rdoc'
  rdoc.title = "simple_oauth #{version}"
  rdoc.rdoc_files.include('README*')
  rdoc.rdoc_files.include('lib/**/*.rb')
end
