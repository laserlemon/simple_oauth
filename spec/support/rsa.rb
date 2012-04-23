module RSAHelpers
  PRIVATE_KEY_PATH = File.expand_path('../fixtures/rsa-private-key', __FILE__)

  def rsa_private_key
    @rsa_private_key ||= File.read(PRIVATE_KEY_PATH)
  end
end

RSpec.configure do |config|
  config.include RSAHelpers
end
