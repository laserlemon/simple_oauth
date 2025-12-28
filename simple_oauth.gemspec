require_relative "lib/simple_oauth/version"

Gem::Specification.new do |spec|
  spec.name = "simple_oauth"
  spec.version = SimpleOauth::VERSION
  spec.authors = ["Steve Richert", "Erik Berlin"]
  spec.email = ["steve.richert@gmail.com", "sferik@gmail.com"]

  spec.summary = "Simply builds and verifies OAuth headers"
  spec.description = spec.summary
  spec.homepage = "https://github.com/laserlemon/simple_oauth"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.0"

  spec.metadata["allowed_push_host"] = "https://rubygems.org"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/laserlemon/simple_oauth"
  spec.metadata["changelog_uri"] = "https://github.com/laserlemon/simple_oauth/blob/master/CHANGELOG.md"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files = Dir.chdir(__dir__) do
    `git ls-files -z`.split("\x0").reject do |f|
      (File.expand_path(f) == __FILE__) ||
        f.start_with?(*%w[bin/ test/ spec/ features/ .git .circleci appveyor Gemfile])
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]
  spec.metadata["rubygems_mfa_required"] = "true"

  spec.add_dependency "base64"
end
