# encoding: utf-8

require 'helper'

describe SimpleOAuth::Header do
  describe ".default_options" do
    let(:default_options){ SimpleOAuth::Header.default_options }

    it "is different every time" do
      expect(SimpleOAuth::Header.default_options).not_to eq default_options
    end

    it "is used for new headers" do
      SimpleOAuth::Header.stub(:default_options => default_options)
      header = SimpleOAuth::Header.new(:get, 'https://api.twitter.com/1/statuses/friendships.json', {})
      expect(header.options).to eq default_options
    end

    it "includes a signature method and an OAuth version" do
      expect(default_options[:signature_method]).not_to be_nil
      expect(default_options[:version]).not_to be_nil
    end
  end

  describe ".escape" do
    it "escapes (most) non-word characters" do
      [' ', '!', '@', '#', '$', '%', '^', '&'].each do |character|
        escaped = SimpleOAuth::Header.escape(character)
        expect(escaped).not_to eq character
        expect(escaped).to eq uri_parser.escape(character, /.*/)
      end
    end

    it "does not escape - . or ~" do
      ['-', '.', '~'].each do |character|
        escaped = SimpleOAuth::Header.escape(character)
        expect(escaped).to eq character
      end
    end

    def self.test_special_characters
      it "escapes non-ASCII characters" do
        expect(SimpleOAuth::Header.escape('é')).to eq '%C3%A9'
      end

      it "escapes multibyte characters" do
        expect(SimpleOAuth::Header.escape('あ')).to eq '%E3%81%82'
      end
    end

    if RUBY_VERSION >= '1.9'
      test_special_characters
    else
      %w(n N e E s S u U).each do |kcode|
        describe %(when $KCODE = "#{kcode}") do
          original_kcode = $KCODE
          begin
            $KCODE = kcode
            test_special_characters
          ensure
            $KCODE = original_kcode
          end
        end
      end
    end
  end

  describe ".unescape" do
    pending
  end

  describe ".parse" do
    let(:header){ SimpleOAuth::Header.new(:get, 'https://api.twitter.com/1/statuses/friends.json', {}) }
    let(:parsed_options){ SimpleOAuth::Header.parse(header) }

    it "returns a hash" do
      expect(parsed_options).to be_a(Hash)
    end

    it "includes the options used to build the header" do
      expect(parsed_options.reject{|k,_| k == :signature }).to eq header.options
    end

    it "includes a signature" do
      expect(header.options).not_to have_key(:signature)
      expect(parsed_options).to have_key(:signature)
      expect(parsed_options[:signature]).not_to be_nil
    end

    it "handles optional 'linear white space'" do
      parsed_header_with_spaces = SimpleOAuth::Header.parse 'OAuth oauth_consumer_key="abcd", oauth_nonce="oLKtec51GQy", oauth_signature="efgh%26mnop", oauth_signature_method="PLAINTEXT", oauth_timestamp="1286977095", oauth_token="ijkl", oauth_version="1.0"'
      expect(parsed_header_with_spaces).to be_a_kind_of(Hash)
      expect(parsed_header_with_spaces.keys.size).to eq 7

      parsed_header_with_tabs = SimpleOAuth::Header.parse 'OAuth oauth_consumer_key="abcd", oauth_nonce="oLKtec51GQy",  oauth_signature="efgh%26mnop",  oauth_signature_method="PLAINTEXT", oauth_timestamp="1286977095", oauth_token="ijkl", oauth_version="1.0"'
      expect(parsed_header_with_tabs).to be_a_kind_of(Hash)
      expect(parsed_header_with_tabs.keys.size).to eq 7

      parsed_header_with_spaces_and_tabs = SimpleOAuth::Header.parse 'OAuth oauth_consumer_key="abcd",  oauth_nonce="oLKtec51GQy",   oauth_signature="efgh%26mnop",   oauth_signature_method="PLAINTEXT",  oauth_timestamp="1286977095",  oauth_token="ijkl",  oauth_version="1.0"'
      expect(parsed_header_with_spaces_and_tabs).to be_a_kind_of(Hash)
      expect(parsed_header_with_spaces_and_tabs.keys.size).to eq 7

      parsed_header_without_spaces = SimpleOAuth::Header.parse 'OAuth oauth_consumer_key="abcd",oauth_nonce="oLKtec51GQy",oauth_signature="efgh%26mnop",oauth_signature_method="PLAINTEXT",oauth_timestamp="1286977095",oauth_token="ijkl",oauth_version="1.0"'
      expect(parsed_header_without_spaces).to be_a_kind_of(Hash)
      expect(parsed_header_without_spaces.keys.size).to eq 7
    end
  end

  describe "#initialize" do
    let(:header){ SimpleOAuth::Header.new(:get, 'HTTPS://api.TWITTER.com:443/1/statuses/friendships.json?foo=bar#anchor', {}) }

    it "stringifies and uppercases the request method" do
      expect(header.method).to eq 'GET'
    end

    it "downcases the scheme and authority" do
      expect(header.url).to match %r(^https://api\.twitter\.com/)
    end

    it "ignores the query and fragment" do
      expect(header.url).to match %r(/1/statuses/friendships\.json$)
    end
  end

  describe "#valid?" do
    context "using the HMAC-SHA1 signature method" do
      it "requires consumer and token secrets" do
        secrets = {:consumer_secret => 'CONSUMER_SECRET', :token_secret => 'TOKEN_SECRET'}
        header = SimpleOAuth::Header.new(:get, 'https://api.twitter.com/1/statuses/friends.json', {}, secrets)
        parsed_header = SimpleOAuth::Header.new(:get, 'https://api.twitter.com/1/statuses/friends.json', {}, header)
        expect(parsed_header).not_to be_valid
        expect(parsed_header).to be_valid(secrets)
      end
    end

    context "using the RSA-SHA1 signature method" do
      it "requires an identical private key" do
        secrets = {:consumer_secret => rsa_private_key}
        header = SimpleOAuth::Header.new(:get, 'https://api.twitter.com/1/statuses/friends.json', {}, secrets.merge(:signature_method => 'RSA-SHA1'))
        parsed_header = SimpleOAuth::Header.new(:get, 'https://api.twitter.com/1/statuses/friends.json', {}, header)
        expect{ parsed_header.valid? }.to raise_error(TypeError)
        expect(parsed_header).to be_valid(secrets)
      end
    end

    context "using the RSA-SHA1 signature method" do
      it "requires consumer and token secrets" do
        secrets = {:consumer_secret => 'CONSUMER_SECRET', :token_secret => 'TOKEN_SECRET'}
        header = SimpleOAuth::Header.new(:get, 'https://api.twitter.com/1/statuses/friends.json', {}, secrets.merge(:signature_method => 'PLAINTEXT'))
        parsed_header = SimpleOAuth::Header.new(:get, 'https://api.twitter.com/1/statuses/friends.json', {}, header)
        expect(parsed_header).not_to be_valid
        expect(parsed_header).to be_valid(secrets)
      end
    end
  end

  describe "#normalized_attributes" do
    let(:header){ SimpleOAuth::Header.new(:get, 'https://api.twitter.com/1/statuses/friends.json', {}) }
    let(:normalized_attributes){ header.send(:normalized_attributes) }

    it "returns a sorted-key, quoted-value and comma-separated list" do
      header.stub(:signed_attributes => {:d => 1, :c => 2, :b => 3, :a => 4})
      expect(normalized_attributes).to eq 'a="4", b="3", c="2", d="1"'
    end

    it "URI encodes its values" do
      header.stub(:signed_attributes => {1 => '!', 2 => '@', 3 => '#', 4 => '$'})
      expect(normalized_attributes).to eq '1="%21", 2="%40", 3="%23", 4="%24"'
    end
  end

  describe "#signed_attributes" do
    it "includes the OAuth signature" do
      header = SimpleOAuth::Header.new(:get, 'https://api.twitter.com/1/statuses/friends.json', {})
      expect(header.send(:signed_attributes)).to have_key(:oauth_signature)
    end
  end

  describe "#attributes" do
    let(:header) do
      options = {}
      SimpleOAuth::Header::ATTRIBUTE_KEYS.each{|k| options[k] = k.to_s.upcase }
      options[:other] = 'OTHER'
      SimpleOAuth::Header.new(:get, 'https://api.twitter.com/1/statuses/friendships.json', {}, options)
    end
    let(:attributes){ header.send(:attributes) }

    it "prepends keys with 'oauth_'" do
      expect(attributes.keys).to be_all{|k| k.to_s =~ /^oauth_/ }
    end

    it "excludes keys not included in the list of valid attributes" do
      expect(attributes.keys).to be_all{|k| k.is_a?(Symbol) }
      expect(attributes).not_to have_key(:oauth_other)
    end

    it "preserves values for valid keys" do
      expect(attributes.size).to eq SimpleOAuth::Header::ATTRIBUTE_KEYS.size
      expect(attributes).to be_all{|k,v| k.to_s == "oauth_#{v.downcase}" }
    end
  end

  describe "#signature" do
    context "calls the appropriate signature method" do
      specify "when using HMAC-SHA1" do
        header = SimpleOAuth::Header.new(:get, 'https://api.twitter.com/1/statuses/friends.json', {}, :signature_method => 'HMAC-SHA1')
        header.should_receive(:hmac_sha1_signature).once.and_return('HMAC_SHA1_SIGNATURE')
        expect(header.send(:signature)).to eq 'HMAC_SHA1_SIGNATURE'
      end

      specify "when using RSA-SHA1" do
        header = SimpleOAuth::Header.new(:get, 'https://api.twitter.com/1/statuses/friends.json', {}, :signature_method => 'RSA-SHA1')
        header.should_receive(:rsa_sha1_signature).once.and_return('RSA_SHA1_SIGNATURE')
        expect(header.send(:signature)).to eq 'RSA_SHA1_SIGNATURE'
      end

      specify "when using PLAINTEXT" do
        header = SimpleOAuth::Header.new(:get, 'https://api.twitter.com/1/statuses/friends.json', {}, :signature_method => 'PLAINTEXT')
        header.should_receive(:plaintext_signature).once.and_return('PLAINTEXT_SIGNATURE')
        expect(header.send(:signature)).to eq 'PLAINTEXT_SIGNATURE'
      end
    end
  end

  describe "#hmac_sha1_signature" do
    it "reproduces a successful Twitter GET" do
      options = {
        :consumer_key => '8karQBlMg6gFOwcf8kcoYw',
        :consumer_secret => '3d0vcHyUiiqADpWxolW8nlDIpSWMlyK7YNgc5Qna2M',
        :nonce => '547fed103e122eecf84c080843eedfe6',
        :signature_method => 'HMAC-SHA1',
        :timestamp => '1286830180',
        :token => '201425800-Sv4sTcgoffmHGkTCue0JnURT8vrm4DiFAkeFNDkh',
        :token_secret => 'T5qa1tF57tfDzKmpM89DHsNuhgOY4NT6DlNLsTFcuQ'
      }
      header = SimpleOAuth::Header.new(:get, 'https://api.twitter.com/1/statuses/friends.json', {}, options)
      expect(header.to_s).to eq 'OAuth oauth_consumer_key="8karQBlMg6gFOwcf8kcoYw", oauth_nonce="547fed103e122eecf84c080843eedfe6", oauth_signature="i9CT6ahDRAlfGX3hKYf78QzXsaw%3D", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1286830180", oauth_token="201425800-Sv4sTcgoffmHGkTCue0JnURT8vrm4DiFAkeFNDkh", oauth_version="1.0"'
    end

    it "reproduces a successful Twitter POST" do
      options = {
        :consumer_key => '8karQBlMg6gFOwcf8kcoYw',
        :consumer_secret => '3d0vcHyUiiqADpWxolW8nlDIpSWMlyK7YNgc5Qna2M',
        :nonce => 'b40a3e0f18590ecdcc0e273f7d7c82f8',
        :signature_method => 'HMAC-SHA1',
        :timestamp => '1286830181',
        :token => '201425800-Sv4sTcgoffmHGkTCue0JnURT8vrm4DiFAkeFNDkh',
        :token_secret => 'T5qa1tF57tfDzKmpM89DHsNuhgOY4NT6DlNLsTFcuQ'
      }
      header = SimpleOAuth::Header.new(:post, 'https://api.twitter.com/1/statuses/update.json', {:status => 'hi, again'}, options)
      expect(header.to_s).to eq 'OAuth oauth_consumer_key="8karQBlMg6gFOwcf8kcoYw", oauth_nonce="b40a3e0f18590ecdcc0e273f7d7c82f8", oauth_signature="mPqSFKejrWWk3ZT9bTQjhO5b2xI%3D", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1286830181", oauth_token="201425800-Sv4sTcgoffmHGkTCue0JnURT8vrm4DiFAkeFNDkh", oauth_version="1.0"'
    end
  end

  describe "#secret" do
    let(:header){ SimpleOAuth::Header.new(:get, 'https://api.twitter.com/1/statuses/friendships.json', {}) }
    let(:secret){ header.send(:secret) }

    it "combines the consumer and token secrets with an ampersand" do
      header.stub(:options => {:consumer_secret => 'CONSUMER_SECRET', :token_secret => 'TOKEN_SECRET'})
      expect(secret).to eq 'CONSUMER_SECRET&TOKEN_SECRET'
    end

    it "URI encodes each secret value before combination" do
      header.stub(:options => {:consumer_secret => 'CONSUM#R_SECRET', :token_secret => 'TOKEN_S#CRET'})
      expect(secret).to eq 'CONSUM%23R_SECRET&TOKEN_S%23CRET'
    end
  end

  describe "#signature_base" do
    let(:header){ SimpleOAuth::Header.new(:get, 'https://api.twitter.com/1/statuses/friendships.json', {}) }
    let(:signature_base){ header.send(:signature_base) }

    it "combines the request method, URL and normalized parameters using ampersands" do
      header.stub(:method => 'METHOD', :url => 'URL', :normalized_params => 'NORMALIZED_PARAMS')
      expect(signature_base).to eq 'METHOD&URL&NORMALIZED_PARAMS'
    end

    it "URI encodes each value before combination" do
      header.stub(:method => 'ME#HOD', :url => 'U#L', :normalized_params => 'NORMAL#ZED_PARAMS')
      expect(signature_base).to eq 'ME%23HOD&U%23L&NORMAL%23ZED_PARAMS'
    end
  end

  describe "#normalized_params" do
    let(:header) do
      header = SimpleOAuth::Header.new(:get, 'https://api.twitter.com/1/statuses/friendships.json', {})
      header.stub(:signature_params => [['A', '4'], ['B', '3'], ['B', '2'], ['C', '1'], ['D[]', '0 ']])
      header
    end
    let(:signature_params){ header.send(:signature_params) }
    let(:normalized_params){ header.send(:normalized_params) }

    it "joins key/value pairs with equal signs and ampersands" do
      expect(normalized_params).to be_a(String)
      parts = normalized_params.split('&')
      expect(parts.size).to eq signature_params.size
      pairs = parts.map{|p| p.split('=') }
      expect(pairs).to be_all{|p| p.size == 2 }
    end
  end

  describe "#signature_params" do
    let(:header){ SimpleOAuth::Header.new(:get, 'https://api.twitter.com/1/statuses/friendships.json', {}) }
    let(:signature_params){ header.send(:signature_params) }

    it "combines OAuth header attributes, body parameters and URL parameters into an flattened array of key/value pairs" do
      header.stub(
        :attributes => {:attribute => 'ATTRIBUTE'},
        :params => {'param' => 'PARAM'},
        :url_params => [['url_param', '1'], ['url_param', '2']]
      )
      expect(signature_params).to eq [
        [:attribute, 'ATTRIBUTE'],
        ['param', 'PARAM'],
        ['url_param', '1'],
        ['url_param', '2']
      ]
    end
  end

  describe "#url_params" do
    it "returns an empty array when the URL has no query parameters" do
      header = SimpleOAuth::Header.new(:get, 'https://api.twitter.com/1/statuses/friendships.json', {})
      expect(header.send(:url_params)).to eq []
    end

    it "returns an array of key/value pairs for each query parameter" do
      header = SimpleOAuth::Header.new(:get, 'https://api.twitter.com/1/statuses/friendships.json?test=TEST', {})
      expect(header.send(:url_params)).to eq [['test', 'TEST']]
    end

    it "sorts values for repeated keys" do
      header = SimpleOAuth::Header.new(:get, 'https://api.twitter.com/1/statuses/friendships.json?test=3&test=1&test=2', {})
      expect(header.send(:url_params)).to eq [['test', '1'], ['test', '2'], ['test', '3']]
    end
  end

  describe "#rsa_sha1_signature" do
    it "reproduces a successful OAuth example GET" do
      options = {
        :consumer_key => 'dpf43f3p2l4k3l03',
        :consumer_secret => rsa_private_key,
        :nonce => '13917289812797014437',
        :signature_method => 'RSA-SHA1',
        :timestamp => '1196666512'
      }
      header = SimpleOAuth::Header.new(:get, 'http://photos.example.net/photos', {:file => 'vacaction.jpg', :size => 'original'}, options)
      expect(header.to_s).to eq 'OAuth oauth_consumer_key="dpf43f3p2l4k3l03", oauth_nonce="13917289812797014437", oauth_signature="jvTp%2FwX1TYtByB1m%2BPbyo0lnCOLIsyGCH7wke8AUs3BpnwZJtAuEJkvQL2%2F9n4s5wUmUl4aCI4BwpraNx4RtEXMe5qg5T1LVTGliMRpKasKsW%2F%2Fe%2BRinhejgCuzoH26dyF8iY2ZZ%2F5D1ilgeijhV%2FvBka5twt399mXwaYdCwFYE%3D", oauth_signature_method="RSA-SHA1", oauth_timestamp="1196666512", oauth_version="1.0"'
    end
  end

  describe "#private_key" do
    pending
  end

  describe "#plaintext_signature" do
    it "reproduces a successful OAuth example GET" do
      options = {
        :consumer_key => 'abcd',
        :consumer_secret => 'efgh',
        :nonce => 'oLKtec51GQy',
        :signature_method => 'PLAINTEXT',
        :timestamp => '1286977095',
        :token => 'ijkl',
        :token_secret => 'mnop'
      }
      header = SimpleOAuth::Header.new(:get, 'http://host.net/resource?name=value', {:name => 'value'}, options)
      expect(header.to_s).to eq 'OAuth oauth_consumer_key="abcd", oauth_nonce="oLKtec51GQy", oauth_signature="efgh%26mnop", oauth_signature_method="PLAINTEXT", oauth_timestamp="1286977095", oauth_token="ijkl", oauth_version="1.0"'
    end
  end
end
