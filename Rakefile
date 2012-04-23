#!/usr/bin/env rake

require 'bundler/gem_tasks'
require 'rake/testtask'
require 'yard'

Rake::TestTask.new do |test|
  test.libs << 'lib' << 'test'
  test.pattern = 'test/**/*_test.rb'
  test.verbose = true
end

task :default => :test

namespace :doc do
  YARD::Rake::YardocTask.new do |task|
    task.files = %w(README.md lib/**/*.rb)
    task.options = %w(--output-dir doc/yard --markup markdown)
  end
end
