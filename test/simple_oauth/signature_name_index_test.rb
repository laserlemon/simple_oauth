# frozen_string_literal: true

require "test_helper"

module SimpleOAuth
  # Tests that looking up a signature method by the name it was registered under allocates
  # nothing, and that the index of those names stays in step with the registry
  class SignatureNameIndexTest < Minitest::Test
    include TestHelpers

    cover "SimpleOAuth::Signature*"

    def teardown
      Signature.reset!
    end

    def test_looking_up_a_registered_name_allocates_nothing
      allocated = allocations { Signature.rsa?("HMAC-SHA1") }

      assert_equal 0, allocated
    end

    def test_looking_up_another_spelling_allocates_its_normalized_name
      allocated = allocations { Signature.rsa?("hmac-sha1") }

      assert_equal 2, allocated
    end

    def test_looking_up_another_spelling_finds_the_method
      assert Signature.registered?("hmac_sha1")
      refute Signature.rsa?("hmac-sha1")
    end

    def test_looking_up_another_spelling_does_not_grow_the_index
      names = Signature.instance_variable_get(:@names).dup
      Signature.registered?("hmac_sha1")
      Signature.registered?("NOT-A-METHOD")

      assert_equal names, Signature.instance_variable_get(:@names)
    end

    def test_unregistering_by_another_spelling_forgets_the_registered_name
      Signature.register("CUSTOM-METHOD") { |_secret, _base| "sig" }
      Signature.unregister("custom_method")

      refute Signature.registered?("CUSTOM-METHOD")
      refute Signature.instance_variable_get(:@names).key?("CUSTOM-METHOD")
    end

    def test_unregistering_keeps_the_names_of_other_methods
      Signature.register("CUSTOM-METHOD") { |_secret, _base| "sig" }
      Signature.unregister("CUSTOM-METHOD")

      assert_equal "hmac_sha1", Signature.instance_variable_get(:@names)["HMAC-SHA1"]
    end

    def test_resetting_forgets_registered_names
      Signature.register("CUSTOM-METHOD") { |_secret, _base| "sig" }
      Signature.reset!

      refute Signature.instance_variable_get(:@names).key?("CUSTOM-METHOD")
    end

    def test_registering_again_under_another_spelling_replaces_the_method
      Signature.register("CUSTOM-METHOD") { |_secret, _base| "first" }
      Signature.register("custom_method") { |_secret, _base| "second" }

      assert_equal "second", Signature.sign("CUSTOM-METHOD", "secret", "base")
    end

    private

    # Counts what a block allocates, once the block has run once, since the first run of a call
    # site allocates the caches Ruby keeps for it
    def allocations
      Array.new(2) do
        before = GC.stat(:total_allocated_objects)
        yield
        GC.stat(:total_allocated_objects) - before
      end.last
    end
  end
end
