require 'helper'

class SimpleOAuthTest < Test::Unit::TestCase
  def test_initialization_argument_formatting
    header = SimpleOAuth::Header.new(:get, 'HTTPS://api.TWITTER.com:443/statuses/friendships.json#anchor', {})

    # HTTP method should be an uppercase string.
    #
    # See: http://oauth.net/core/1.0/#rfc.section.9.1.3
    assert_equal 'GET', header.method

    # Request URL should downcase the scheme and authority parts as well as
    # remove the query and fragment parts.
    #
    # See: http://oauth.net/core/1.0/#rfc.section.9.1.2
    assert_equal 'https://api.twitter.com/statuses/friendships.json', header.url
  end

  def test_default_options
    # Default header options should change with each call due to generation of
    # a unique "timestamp" and "nonce" value combination.
    default_options = SimpleOAuth::Header.default_options
    assert_not_equal default_options, SimpleOAuth::Header.default_options

    SimpleOAuth::Header.stubs(:default_options).returns(default_options)
    header = SimpleOAuth::Header.new(:get, 'https://api.twitter.com/statuses/friendships.json', {})

    # Given no options argument, header options defer to the default options.
    assert_equal default_options, header.options

    # Default options should include a signature method and the OAuth version.
    assert_equal 'HMAC-SHA1', default_options[:signature_method]
    assert_equal '1.0', default_options[:version]
  end
end
