require "helper"

describe SimpleOAuth::Header do
  describe ".default_options" do
    let(:default_options) { described_class.default_options }

    it "is different every time" do
      expect(described_class.default_options).not_to eq default_options
    end

    it "is used for new headers" do
      allow(described_class).to receive(:default_options).and_return(default_options)
      header = described_class.new(:get, "https://api.twitter.com/1/statuses/friendships.json", {})
      expect(header.options).to eq default_options
    end

    it "includes a signature method" do
      expect(default_options[:signature_method]).not_to be_nil
    end

    it "includes an OAuth version" do
      expect(default_options[:version]).not_to be_nil
    end
  end

  describe ".escape" do
    it "escapes (most) non-word characters", :aggregate_failures do
      [" ", "!", "@", "#", "$", "%", "^", "&"].each do |character|
        escaped = described_class.escape(character)
        expect(escaped).not_to eq character
        expect(escaped).to eq uri_parser.escape(character, /.*/)
      end
    end

    it "does not escape - . or ~" do
      ["-", ".", "~"].each do |character|
        escaped = described_class.escape(character)
        expect(escaped).to eq character
      end
    end

    it "escapes non-ASCII characters" do
      expect(described_class.escape("é")).to eq "%C3%A9"
    end

    it "escapes multibyte characters" do
      expect(described_class.escape("あ")).to eq "%E3%81%82"
    end
  end

  describe ".unescape" do
    it "unescapes percent-encoded characters" do
      expect(described_class.unescape("%C3%A9")).to eq "é"
    end

    it "unescapes multibyte characters" do
      expect(described_class.unescape("%E3%81%82")).to eq "あ"
    end

    it "returns unencoded characters as-is" do
      expect(described_class.unescape("hello")).to eq "hello"
    end
  end

  describe ".parse" do
    let(:header) { described_class.new(:get, "https://api.twitter.com/1/statuses/friends.json", {}) }
    let(:parsed_options) { described_class.parse(header) }

    it "returns a hash" do
      expect(parsed_options).to be_a(Hash)
    end

    it "includes the options used to build the header" do
      expect(parsed_options.except(:signature)).to eq header.options
    end

    it "does not include signature in header options" do
      expect(header.options).not_to have_key(:signature)
    end

    it "includes a signature in parsed options" do
      expect(parsed_options).to have_key(:signature)
    end

    it "has a non-nil signature" do
      expect(parsed_options[:signature]).not_to be_nil
    end

    it "parses header with spaces after commas" do
      header_with_spaces = 'OAuth oauth_consumer_key="abcd", oauth_nonce="oLKtec51GQy", ' \
                           'oauth_signature="efgh%26mnop", oauth_signature_method="PLAINTEXT", ' \
                           'oauth_timestamp="1286977095", oauth_token="ijkl", oauth_version="1.0"'
      parsed_header_with_spaces = described_class.parse(header_with_spaces)
      expect(parsed_header_with_spaces.keys.size).to eq 7
    end

    it "parses header with multiple spaces after commas" do
      header_with_tabs = 'OAuth oauth_consumer_key="abcd", oauth_nonce="oLKtec51GQy",  ' \
                         'oauth_signature="efgh%26mnop",  oauth_signature_method="PLAINTEXT", ' \
                         'oauth_timestamp="1286977095", oauth_token="ijkl", oauth_version="1.0"'
      parsed_header_with_tabs = described_class.parse(header_with_tabs)
      expect(parsed_header_with_tabs.keys.size).to eq 7
    end

    it "parses header with mixed whitespace after commas" do
      header_with_spaces_and_tabs = 'OAuth oauth_consumer_key="abcd",  oauth_nonce="oLKtec51GQy",   ' \
                                    'oauth_signature="efgh%26mnop",   oauth_signature_method="PLAINTEXT",  ' \
                                    'oauth_timestamp="1286977095",  oauth_token="ijkl",  oauth_version="1.0"'
      parsed_header_with_spaces_and_tabs = described_class.parse(header_with_spaces_and_tabs)
      expect(parsed_header_with_spaces_and_tabs.keys.size).to eq 7
    end

    it "parses header without spaces after commas" do
      header_without_spaces = 'OAuth oauth_consumer_key="abcd",oauth_nonce="oLKtec51GQy",' \
                              'oauth_signature="efgh%26mnop",oauth_signature_method="PLAINTEXT",' \
                              'oauth_timestamp="1286977095",oauth_token="ijkl",oauth_version="1.0"'
      parsed_header_without_spaces = described_class.parse(header_without_spaces)
      expect(parsed_header_without_spaces.keys.size).to eq 7
    end
  end

  describe "#initialize" do
    let(:header) do
      described_class.new(:get, "HTTPS://api.TWITTER.com:443/1/statuses/friendships.json?foo=bar#anchor", {})
    end

    it "stringifies and uppercases the request method" do
      expect(header.method).to eq "GET"
    end

    it "downcases the scheme and authority" do
      expect(header.url).to match %r{^https://api\.twitter\.com/}
    end

    it "ignores the query and fragment" do
      expect(header.url).to match %r{/1/statuses/friendships\.json$}
    end
  end

  describe "#valid?" do
    context "when using the HMAC-SHA1 signature method" do
      let(:secrets) { {consumer_secret: "CONSUMER_SECRET", token_secret: "TOKEN_SECRET"} }
      let(:header) { described_class.new(:get, "https://api.twitter.com/1/statuses/friends.json", {}, secrets) }
      let(:parsed_header) { described_class.new(:get, "https://api.twitter.com/1/statuses/friends.json", {}, header) }

      it "is not valid without secrets" do
        expect(parsed_header).not_to be_valid
      end

      it "is valid with consumer and token secrets" do
        expect(parsed_header).to be_valid(secrets)
      end
    end

    context "when using the RSA-SHA1 signature method" do
      let(:secrets) { {consumer_secret: rsa_private_key} }
      let(:header) do
        described_class.new(:get, "https://api.twitter.com/1/statuses/friends.json", {},
          secrets.merge(signature_method: "RSA-SHA1"))
      end
      let(:parsed_header) { described_class.new(:get, "https://api.twitter.com/1/statuses/friends.json", {}, header) }

      it "raises TypeError without private key" do
        expect { parsed_header.valid? }.to raise_error(TypeError)
      end

      it "is valid with identical private key" do
        expect(parsed_header).to be_valid(secrets)
      end
    end

    context "when using the PLAINTEXT signature method" do
      let(:secrets) { {consumer_secret: "CONSUMER_SECRET", token_secret: "TOKEN_SECRET"} }
      let(:header) do
        described_class.new(:get, "https://api.twitter.com/1/statuses/friends.json", {},
          secrets.merge(signature_method: "PLAINTEXT"))
      end
      let(:parsed_header) { described_class.new(:get, "https://api.twitter.com/1/statuses/friends.json", {}, header) }

      it "is not valid without secrets" do
        expect(parsed_header).not_to be_valid
      end

      it "is valid with consumer and token secrets" do
        expect(parsed_header).to be_valid(secrets)
      end
    end
  end

  describe "#normalized_attributes" do
    let(:header) { described_class.new(:get, "https://api.twitter.com/1/statuses/friends.json", {}) }
    let(:normalized_attributes) { header.send(:normalized_attributes) }

    it "returns a sorted-key, quoted-value and comma-separated list" do
      allow(header).to receive(:signed_attributes).and_return(d: 1, c: 2, b: 3, a: 4)
      expect(normalized_attributes).to eq 'a="4", b="3", c="2", d="1"'
    end

    it "URI encodes its values" do
      allow(header).to receive(:signed_attributes).and_return(1 => "!", 2 => "@", 3 => "#", 4 => "$")
      expect(normalized_attributes).to eq '1="%21", 2="%40", 3="%23", 4="%24"'
    end
  end

  describe "#signed_attributes" do
    it "includes the OAuth signature" do
      header = described_class.new(:get, "https://api.twitter.com/1/statuses/friends.json", {})
      expect(header.send(:signed_attributes)).to have_key(:oauth_signature)
    end
  end

  describe "#attributes" do
    let(:header) do
      options = {}
      SimpleOAuth::Header::ATTRIBUTE_KEYS.each { |k| options[k] = k.to_s.upcase }
      options[:other] = "OTHER"
      described_class.new(:get, "https://api.twitter.com/1/statuses/friendships.json", {}, options)
    end

    it "prepends keys with 'oauth_'" do
      header.options[:ignore_extra_keys] = true
      expect(header.send(:attributes).keys).to(be_all { |k| k.to_s =~ /^oauth_/ })
    end

    it "has only symbol keys" do
      header.options[:ignore_extra_keys] = true
      expect(header.send(:attributes).keys).to(be_all { |k| k.is_a?(Symbol) })
    end

    it "excludes keys not included in the list of valid attributes" do
      header.options[:ignore_extra_keys] = true
      expect(header.send(:attributes)).not_to have_key(:oauth_other)
    end

    it "preserves values for valid keys" do
      header.options[:ignore_extra_keys] = true
      expect(header.send(:attributes)).to(be_all { |k, v| k.to_s == "oauth_#{v.downcase}" })
    end

    it "has the same number of attributes as ATTRIBUTE_KEYS" do
      header.options[:ignore_extra_keys] = true
      expect(header.send(:attributes).size).to eq SimpleOAuth::Header::ATTRIBUTE_KEYS.size
    end

    it "raises exception for extra keys" do
      expect do
        header.send(:attributes)
      end.to raise_error(RuntimeError,
        "SimpleOAuth: Found extra option keys not matching ATTRIBUTE_KEYS:\n  [:other]")
    end
  end

  describe "#signature" do
    context "when using HMAC-SHA1" do
      let(:header) { described_class.new(:get, "https://api.twitter.com/1/statuses/friends.json", {}, signature_method: "HMAC-SHA1") }

      it "calls hmac_sha1_signature once" do
        allow(header).to receive(:hmac_sha1_signature).and_return("HMAC_SHA1_SIGNATURE")
        header.send(:signature)
        expect(header).to have_received(:hmac_sha1_signature).once
      end

      it "returns the HMAC-SHA1 signature" do
        allow(header).to receive(:hmac_sha1_signature).and_return("HMAC_SHA1_SIGNATURE")
        expect(header.send(:signature)).to eq "HMAC_SHA1_SIGNATURE"
      end
    end

    context "when using RSA-SHA1" do
      let(:header) { described_class.new(:get, "https://api.twitter.com/1/statuses/friends.json", {}, signature_method: "RSA-SHA1") }

      it "calls rsa_sha1_signature once" do
        allow(header).to receive(:rsa_sha1_signature).and_return("RSA_SHA1_SIGNATURE")
        header.send(:signature)
        expect(header).to have_received(:rsa_sha1_signature).once
      end

      it "returns the RSA-SHA1 signature" do
        allow(header).to receive(:rsa_sha1_signature).and_return("RSA_SHA1_SIGNATURE")
        expect(header.send(:signature)).to eq "RSA_SHA1_SIGNATURE"
      end
    end

    context "when using PLAINTEXT" do
      let(:header) { described_class.new(:get, "https://api.twitter.com/1/statuses/friends.json", {}, signature_method: "PLAINTEXT") }

      it "calls plaintext_signature once" do
        allow(header).to receive(:plaintext_signature).and_return("PLAINTEXT_SIGNATURE")
        header.send(:signature)
        expect(header).to have_received(:plaintext_signature).once
      end

      it "returns the PLAINTEXT signature" do
        allow(header).to receive(:plaintext_signature).and_return("PLAINTEXT_SIGNATURE")
        expect(header.send(:signature)).to eq "PLAINTEXT_SIGNATURE"
      end
    end
  end

  describe "#hmac_sha1_signature" do
    context "with Twitter GET request" do
      let(:options) do
        {
          consumer_key: "8karQBlMg6gFOwcf8kcoYw",
          consumer_secret: "3d0vcHyUiiqADpWxolW8nlDIpSWMlyK7YNgc5Qna2M",
          nonce: "547fed103e122eecf84c080843eedfe6",
          signature_method: "HMAC-SHA1",
          timestamp: "1286830180",
          token: "201425800-Sv4sTcgoffmHGkTCue0JnURT8vrm4DiFAkeFNDkh",
          token_secret: "T5qa1tF57tfDzKmpM89DHsNuhgOY4NT6DlNLsTFcuQ"
        }
      end
      let(:header) { described_class.new(:get, "https://api.twitter.com/1/statuses/friends.json", {}, options) }
      let(:expected) do
        'OAuth oauth_consumer_key="8karQBlMg6gFOwcf8kcoYw", ' \
          'oauth_nonce="547fed103e122eecf84c080843eedfe6", oauth_signature="i9CT6ahDRAlfGX3hKYf78QzXsaw%3D", ' \
          'oauth_signature_method="HMAC-SHA1", oauth_timestamp="1286830180", ' \
          'oauth_token="201425800-Sv4sTcgoffmHGkTCue0JnURT8vrm4DiFAkeFNDkh", oauth_version="1.0"'
      end

      it "reproduces a successful Twitter GET" do
        expect(header.to_s).to eq expected
      end
    end

    context "with Twitter POST request" do
      let(:options) do
        {
          consumer_key: "8karQBlMg6gFOwcf8kcoYw",
          consumer_secret: "3d0vcHyUiiqADpWxolW8nlDIpSWMlyK7YNgc5Qna2M",
          nonce: "b40a3e0f18590ecdcc0e273f7d7c82f8",
          signature_method: "HMAC-SHA1",
          timestamp: "1286830181",
          token: "201425800-Sv4sTcgoffmHGkTCue0JnURT8vrm4DiFAkeFNDkh",
          token_secret: "T5qa1tF57tfDzKmpM89DHsNuhgOY4NT6DlNLsTFcuQ"
        }
      end
      let(:header) do
        described_class.new(:post, "https://api.twitter.com/1/statuses/update.json", {status: "hi, again"}, options)
      end
      let(:expected) do
        'OAuth oauth_consumer_key="8karQBlMg6gFOwcf8kcoYw", ' \
          'oauth_nonce="b40a3e0f18590ecdcc0e273f7d7c82f8", oauth_signature="mPqSFKejrWWk3ZT9bTQjhO5b2xI%3D", ' \
          'oauth_signature_method="HMAC-SHA1", oauth_timestamp="1286830181", ' \
          'oauth_token="201425800-Sv4sTcgoffmHGkTCue0JnURT8vrm4DiFAkeFNDkh", oauth_version="1.0"'
      end

      it "reproduces a successful Twitter POST" do
        expect(header.to_s).to eq expected
      end
    end
  end

  describe "#secret" do
    let(:header) { described_class.new(:get, "https://api.twitter.com/1/statuses/friendships.json", {}) }
    let(:secret) { header.send(:secret) }

    it "combines the consumer and token secrets with an ampersand" do
      allow(header).to receive(:options).and_return(consumer_secret: "CONSUMER_SECRET",
        token_secret: "TOKEN_SECRET")
      expect(secret).to eq "CONSUMER_SECRET&TOKEN_SECRET"
    end

    it "URI encodes each secret value before combination" do
      allow(header).to receive(:options).and_return(consumer_secret: "CONSUM#R_SECRET",
        token_secret: "TOKEN_S#CRET")
      expect(secret).to eq "CONSUM%23R_SECRET&TOKEN_S%23CRET"
    end
  end

  describe "#signature_base" do
    let(:header) { described_class.new(:get, "https://api.twitter.com/1/statuses/friendships.json", {}) }
    let(:signature_base) { header.send(:signature_base) }

    it "combines the request method, URL and normalized parameters using ampersands" do
      allow(header).to receive_messages(method: "METHOD", url: "URL", normalized_params: "NORMALIZED_PARAMS")
      expect(signature_base).to eq "METHOD&URL&NORMALIZED_PARAMS"
    end

    it "URI encodes each value before combination" do
      allow(header).to receive_messages(method: "ME#HOD", url: "U#L", normalized_params: "NORMAL#ZED_PARAMS")
      expect(signature_base).to eq "ME%23HOD&U%23L&NORMAL%23ZED_PARAMS"
    end
  end

  describe "#normalized_params" do
    let(:header) do
      header = described_class.new(:get, "https://api.twitter.com/1/statuses/friendships.json", {})
      allow(header).to receive(:signature_params).and_return([%w[A 4], %w[B 3], %w[B 2], %w[C 1], ["D[]", "0 "]])
      header
    end
    let(:signature_params) { header.send(:signature_params) }
    let(:normalized_params) { header.send(:normalized_params) }

    it "returns a string" do
      expect(normalized_params).to be_a(String)
    end

    it "joins pairs with ampersands matching signature_params count" do
      parts = normalized_params.split("&")
      expect(parts.size).to eq signature_params.size
    end

    it "joins key/value with equal signs" do
      pairs = normalized_params.split("&").collect { |p| p.split("=") }
      expect(pairs).to(be_all { |p| p.size == 2 })
    end
  end

  describe "#signature_params" do
    let(:header) { described_class.new(:get, "https://api.twitter.com/1/statuses/friendships.json", {}) }
    let(:signature_params) do
      allow(header).to receive_messages(attributes: {attribute: "ATTRIBUTE"}, params: {"param" => "PARAM"},
        url_params: [%w[url_param 1], %w[url_param 2]])
      header.send(:signature_params)
    end
    let(:expected) { [[:attribute, "ATTRIBUTE"], %w[param PARAM], %w[url_param 1], %w[url_param 2]] }

    it "combines OAuth header attributes, body parameters and URL parameters into a flattened array" do
      expect(signature_params).to eq expected
    end
  end

  describe "#url_params" do
    it "returns an empty array when the URL has no query parameters" do
      header = described_class.new(:get, "https://api.twitter.com/1/statuses/friendships.json", {})
      expect(header.send(:url_params)).to eq []
    end

    it "returns an array of key/value pairs for each query parameter" do
      header = described_class.new(:get, "https://api.twitter.com/1/statuses/friendships.json?test=TEST", {})
      expect(header.send(:url_params)).to eq [%w[test TEST]]
    end

    it "sorts values for repeated keys" do
      header = described_class.new(:get,
        "https://api.twitter.com/1/statuses/friendships.json?test=3&test=1&test=2", {})
      expect(header.send(:url_params)).to eq [%w[test 1], %w[test 2], %w[test 3]]
    end
  end

  describe "#rsa_sha1_signature" do
    let(:options) do
      {
        consumer_key: "dpf43f3p2l4k3l03",
        consumer_secret: rsa_private_key,
        nonce: "13917289812797014437",
        signature_method: "RSA-SHA1",
        timestamp: "1196666512"
      }
    end
    let(:header) do
      described_class.new(:get, "http://photos.example.net/photos", {file: "vacaction.jpg", size: "original"}, options)
    end
    let(:expected) do
      'OAuth oauth_consumer_key="dpf43f3p2l4k3l03", oauth_nonce="13917289812797014437", ' \
        'oauth_signature="jvTp%2FwX1TYtByB1m%2BPbyo0lnCOLIsyGCH7wke8AUs3BpnwZJtAuEJkvQL2%2F9n4s5wUmUl4aCI4BwpraNx4RtEXMe' \
        '5qg5T1LVTGliMRpKasKsW%2F%2Fe%2BRinhejgCuzoH26dyF8iY2ZZ%2F5D1ilgeijhV%2FvBka5twt399mXwaYdCwFYE%3D", ' \
        'oauth_signature_method="RSA-SHA1", oauth_timestamp="1196666512", oauth_version="1.0"'
    end

    it "reproduces a successful OAuth example GET" do
      expect(header.to_s).to eq expected
    end
  end

  describe "#private_key" do
    it "returns an RSA private key from consumer_secret" do
      header = described_class.new(:get, "https://example.com", {}, consumer_secret: rsa_private_key)
      expect(header.send(:private_key)).to be_a(OpenSSL::PKey::RSA)
    end
  end

  describe "#plaintext_signature" do
    let(:options) do
      {
        consumer_key: "abcd",
        consumer_secret: "efgh",
        nonce: "oLKtec51GQy",
        signature_method: "PLAINTEXT",
        timestamp: "1286977095",
        token: "ijkl",
        token_secret: "mnop"
      }
    end
    let(:header) { described_class.new(:get, "http://host.net/resource?name=value", {name: "value"}, options) }
    let(:expected) do
      'OAuth oauth_consumer_key="abcd", oauth_nonce="oLKtec51GQy", oauth_signature="efgh%26mnop", ' \
        'oauth_signature_method="PLAINTEXT", oauth_timestamp="1286977095", oauth_token="ijkl", oauth_version="1.0"'
    end

    it "reproduces a successful OAuth example GET" do
      expect(header.to_s).to eq expected
    end
  end
end
