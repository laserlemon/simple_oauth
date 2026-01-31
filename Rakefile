require "bundler/gem_tasks"
# Override release task to skip gem push (handled by GitHub Actions with attestations)
Rake::Task["release"].clear
desc "Build gem and create tag (gem push handled by CI)"
task release: %w[build release:guard_clean release:source_control_push]

require "rake/testtask"
Rake::TestTask.new(:test) do |t|
  t.libs << "test"
  t.libs << "lib"
  t.test_files = FileList["test/**/*_test.rb"]
end

require "rubocop/rake_task"
RuboCop::RakeTask.new

require "standard/rake"

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

task default: %i[test rubocop standard mutant yardstick steep]
