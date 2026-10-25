# frozen_string_literal: true

source "https://rubygems.org"

# Specify your gem's dependencies in simple_oauth.gemspec
gemspec

# The tests compare against base64 as a reference for the pack("m0") the library uses
gem "base64", ">= 0.3"
# Duel requires Ruby 3.4 or later
gem "duel" if Gem::Version.new(RUBY_VERSION) >= Gem::Version.new("3.4")
gem "minitest", ">= 6.0"
gem "mutant-minitest", ">= 0.13"
gem "rake", ">= 13.3.1"
gem "rbs", ">= 4"
gem "rubocop", ">= 1.82.1"
gem "rubocop-minitest", ">= 0.36"
gem "rubocop-performance", ">= 1.26.1"
gem "rubocop-rake", ">= 0.7.1"
gem "simplecov", ">= 1"
# For Duel's profiles of regressions (StackProf runs on CRuby only)
gem "stackprof", platforms: :mri
gem "standard", ">= 1.53"
gem "steep", ">= 2"
gem "webmock", ">= 3.26.1"
gem "yard", ">= 0.9.38"
gem "yardstick", ">= 0.9.9"
