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

  def test_attributes
    attribute_options = SimpleOAuth::Header::ATTRIBUTE_KEYS.inject({}){|o,a| o.merge(a => a.to_s.upcase) }
    options = attribute_options.merge(:other => 'OTHER')
    header = SimpleOAuth::Header.new(:get, 'https://api.twitter.com/statuses/friendships.json', {}, options)
    attributes = header.send(:attributes)

    # OAuth header attributes are all to begin with the "oauth_" prefix.
    assert attributes.all?{|k,v| k.to_s =~ /^oauth_/ }

    # Custom options not included in the list of valid attribute keys should
    # not be included in the header attributes.
    assert !attributes.key?(:oauth_other)

    # Valid attribute option values should be preserved.
    assert_equal attribute_options.size, attributes.size
    assert attributes.all?{|k,v| k.to_s == "oauth_#{v.downcase}" }
  end

  def test_encode
    # Non-word characters should be URL encoded...
    [' ', '!', '@', '$', '%', '^', '&'].each do |character|
      encoded = SimpleOAuth::Header.encode(character)
      assert_not_equal character, encoded
      assert_equal URI.encode(character, /.*/), encoded
    end

    # ...except for the "-", "." and "~" characters.
    ['-', '.', '~'].each do |character|
      assert_equal character, SimpleOAuth::Header.encode(character)
    end
  end

  def test_url_params
    # A URL with no query parameters should produce empty +url_params+
    header = SimpleOAuth::Header.new(:get, 'https://api.twitter.com/statuses/friendships.json', {})
    assert_equal [], header.send(:url_params)

    # A URL with query parameters should return a hash having array values
    # containing the given query parameters.
    header = SimpleOAuth::Header.new(:get, 'https://api.twitter.com/statuses/friendships.json?test=TEST', {})
    url_params = header.send(:url_params)
    assert_kind_of Array, url_params
    assert_equal [['test', 'TEST']], url_params

    # If a query parameter is repeated, the values should be sorted.
    header = SimpleOAuth::Header.new(:get, 'https://api.twitter.com/statuses/friendships.json?test=1&test=2', {})
    assert_equal [['test', '1'], ['test', '2']], header.send(:url_params)
  end
end
