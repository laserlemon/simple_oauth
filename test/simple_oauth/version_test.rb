# frozen_string_literal: true

require "test_helper"

module SimpleOAuth
  # Tests for the version the gem reports
  class VersionTest < Minitest::Test
    cover "SimpleOAuth*"

    def test_version_is_defined_on_the_library_module
      assert_match(/\A\d+\.\d+\.\d+/, SimpleOAuth::VERSION)
    end

    def test_version_is_frozen
      assert_predicate SimpleOAuth::VERSION, :frozen?
    end
  end
end
