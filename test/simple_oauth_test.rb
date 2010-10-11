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
    [' ', '!', '@', '#', '$', '%', '^', '&'].each do |character|
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

  def test_signature_params
    header = SimpleOAuth::Header.new(:get, 'https://api.twitter.com/statuses/friendships.json', {})
    header.stubs(:attributes).returns(:attribute => 'ATTRIBUTE')
    header.stubs(:params).returns('param' => 'PARAM')
    header.stubs(:url_params).returns([['url_param', '1'], ['url_param', '2']])

    # Should combine OAuth header attributes, body parameters and URL
    # parameters into an array of key value pairs.
    signature_params = header.send(:signature_params)
    assert_kind_of Array, signature_params
    assert_equal [:attribute, 'param', 'url_param', 'url_param'], signature_params.map(&:first)
    assert_equal ['ATTRIBUTE', 'PARAM', '1', '2'], signature_params.map(&:last)
  end

  def test_normalized_params
    header = SimpleOAuth::Header.new(:get, 'https://api.twitter.com/statuses/friendships.json', {})
    header.stubs(:signature_params).returns([['A', '4'], ['B', '3'], ['B', '2'], ['C', '1'], ['D[]', '0 ']])

    # The +normalized_params+ string should join key=value pairs with
    # ampersands.
    signature_params = header.send(:signature_params)
    normalized_params = header.send(:normalized_params)
    parts = normalized_params.split('&')
    pairs = parts.map{|p| p.split('=') }
    assert_kind_of String, normalized_params
    assert_equal signature_params.size, parts.size
    assert pairs.all?{|p| p.size == 2 }

    # The signature parameters should be sorted and the keys/values URL encoded
    # first.
    assert_equal signature_params.sort_by(&:to_s), pairs.map{|k,v| [URI.decode(k), URI.decode(v)] }
  end

  def test_signature_base
    header = SimpleOAuth::Header.new(:get, 'https://api.twitter.com/statuses/friendships.json', {})
    header.stubs(:method).returns('METHOD')
    header.stubs(:url).returns('URL')
    header.stubs(:normalized_params).returns('NORMALIZED_PARAMS')

    # Should combine HTTP method, URL and normalized parameters string using
    # ampersands.
    assert_equal 'METHOD&URL&NORMALIZED_PARAMS', header.send(:signature_base)

    header.stubs(:method).returns('ME#HOD')
    header.stubs(:url).returns('U#L')
    header.stubs(:normalized_params).returns('NORMAL#ZED_PARAMS')

    # Each of the three combined values should be URL encoded.
    assert_equal 'ME%23HOD&U%23L&NORMAL%23ZED_PARAMS', header.send(:signature_base)
  end

  def test_secret
    header = SimpleOAuth::Header.new(:get, 'https://api.twitter.com/statuses/friendships.json', {})
    header.stubs(:options).returns(:consumer_secret => 'CONSUMER_SECRET', :token_secret => 'TOKEN_SECRET')

    # Should combine the consumer and token secrets with an ampersand.
    assert_equal 'CONSUMER_SECRET&TOKEN_SECRET', header.send(:secret)

    header.stubs(:options).returns(:consumer_secret => 'CONSUM#R_SECRET', :token_secret => 'TOKEN_S#CRET')

    # Should URL encode each secret value before combination.
    assert_equal 'CONSUM%23R_SECRET&TOKEN_S%23CRET', header.send(:secret)
  end

  def test_hmac_sha1_signature
    # Reproduce an actual successful call to the Twitter API using the
    # HMAC-SHA1 signature method, GETting a list of friends.
    options = {
      :consumer_key => '8karQBlMg6gFOwcf8kcoYw',
      :consumer_secret => '3d0vcHyUiiqADpWxolW8nlDIpSWMlyK7YNgc5Qna2M',
      :nonce => '547fed103e122eecf84c080843eedfe6',
      #:signature_method => 'HMAC-SHA1',
      :timestamp => '1286830180',
      :token => '201425800-Sv4sTcgoffmHGkTCue0JnURT8vrm4DiFAkeFNDkh',
      :token_secret => 'T5qa1tF57tfDzKmpM89DHsNuhgOY4NT6DlNLsTFcuQ'
    }
    successful = 'OAuth oauth_consumer_key="8karQBlMg6gFOwcf8kcoYw", oauth_nonce="547fed103e122eecf84c080843eedfe6", oauth_signature="i9CT6ahDRAlfGX3hKYf78QzXsaw%3D", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1286830180", oauth_token="201425800-Sv4sTcgoffmHGkTCue0JnURT8vrm4DiFAkeFNDkh", oauth_version="1.0"'
    header = SimpleOAuth::Header.new(:get, 'https://api.twitter.com/1/statuses/friends.json', {}, options)
    assert_equal successful, header.to_s

    # Reproduce a successful Twitter call, POSTing a new status.
    options.merge!(
      :nonce => 'b40a3e0f18590ecdcc0e273f7d7c82f8',
      :timestamp => '1286830181'
    )
    successful = 'OAuth oauth_consumer_key="8karQBlMg6gFOwcf8kcoYw", oauth_nonce="b40a3e0f18590ecdcc0e273f7d7c82f8", oauth_signature="mPqSFKejrWWk3ZT9bTQjhO5b2xI%3D", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1286830181", oauth_token="201425800-Sv4sTcgoffmHGkTCue0JnURT8vrm4DiFAkeFNDkh", oauth_version="1.0"'
    header = SimpleOAuth::Header.new(:post, 'https://api.twitter.com/1/statuses/update.json', {:status => 'hi, again'}, options)
    assert_equal successful, header.to_s
  end

  def test_signed_attributes
    header = SimpleOAuth::Header.new(:get, 'https://api.twitter.com/1/statuses/friends.json', {})
    assert header.send(:signed_attributes).keys.include?(:oauth_signature)
  end

  def test_normalized_attributes
    header = SimpleOAuth::Header.new(:get, 'https://api.twitter.com/1/statuses/friends.json', {})
    header.stubs(:signed_attributes).returns(:d => 1, :c => 2, :b => 3, :a => 4)

    # Should return the OAuth header attributes, sorted by name, with quoted
    # values and comma-separated.
    assert_equal 'a="4", b="3", c="2", d="1"', header.send(:normalized_attributes)

    # Values should also be URL encoded.
    header.stubs(:signed_attributes).returns(1 => '!', 2 => '@', 3 => '#', 4 => '$')
    assert_equal '1="%21", 2="%40", 3="%23", 4="%24"', header.send(:normalized_attributes)
  end

  def test_to_s
    header = SimpleOAuth::Header.new(:get, 'https://api.twitter.com/1/statuses/friends.json', {})
    assert_equal "OAuth #{header.send(:normalized_attributes)}", header.to_s
  end
end
