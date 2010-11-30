major, minor, patch = RUBY_VERSION.split('.')

if major.to_i == 1 && minor.to_i < 9
  class Object
    def tap
      yield self
      self
    end
  end
end
