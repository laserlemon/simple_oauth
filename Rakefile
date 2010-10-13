require 'rake'
require 'rake/testtask'
require 'rake/rdoctask'
require 'bundler'

Bundler::GemHelper.install_tasks

Rake::TestTask.new do |test|
  test.libs << 'lib' << 'test'
  test.pattern = 'test/**/*_test.rb'
  test.verbose = true
end

task :default => :test

Rake::RDocTask.new do |rdoc|
  version = SimpleOAuth::Version::STRING
  rdoc.rdoc_dir = 'rdoc'
  rdoc.title = "simple_oauth #{version}"
  rdoc.rdoc_files.include('README*')
  rdoc.rdoc_files.include('lib/**/*.rb')
end

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

def gemspec
  @gemspec ||= begin
    file = File.expand_path('../simple_oauth.gemspec', __FILE__)
    eval(File.read(file), binding, file)
  end
end

desc 'Validate the gemspec'
task :gemspec do
  gemspec.validate
end
