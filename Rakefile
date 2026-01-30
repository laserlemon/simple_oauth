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

require "yard"
YARD::Rake::YardocTask.new(:yard)

desc "Check documentation coverage"
task :yardstick do
  require "yardstick/rake/verify"
  Yardstick::Rake::Verify.new(:verify_docs) do |verify|
    verify.threshold = 100
  end
  Rake::Task[:verify_docs].invoke
end

desc "Run type checker"
task :steep do
  system("bundle", "exec", "steep", "check") || exit(1)
end

task default: %i[test mutant rubocop standard yardstick steep]
