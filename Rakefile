require "bundler/gem_tasks"
require "rake/testtask"
require "rubocop/rake_task"
require "standard/rake"

Rake::TestTask.new(:test) do |t|
  t.libs << "test"
  t.libs << "lib"
  t.test_files = FileList["test/**/*_test.rb"]
end

RuboCop::RakeTask.new

desc "Run mutation tests"
task :mutant do
  system("bundle", "exec", "mutant", "run") || exit(1)
end

task default: %i[test rubocop standard mutant]
