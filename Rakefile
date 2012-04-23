#!/usr/bin/env rake

require 'bundler/gem_tasks'
require 'rspec/core/rake_task'
require 'yard'

RSpec::Core::RakeTask.new(:spec)

task :default => :spec

namespace :doc do
  YARD::Rake::YardocTask.new do |task|
    task.files = %w(README.md lib/**/*.rb)
    task.options = %w(--output-dir doc/yard --markup markdown)
  end
end
