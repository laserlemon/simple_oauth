require "test_helper"

module SimpleOAuth
  class HeaderEscapeTest < Minitest::Test
    cover "SimpleOAuth::Header*"

    # .escape tests

    def test_escape_escapes_non_word_characters
      [" ", "!", "@", "#", "$", "%", "^", "&"].each do |character|
        escaped = SimpleOAuth::Header.escape(character)

        refute_equal character, escaped
        assert_equal URI::RFC2396_PARSER.escape(character, /.*/), escaped
      end
    end

    def test_escape_does_not_escape_dash_dot_or_tilde
      ["-", ".", "~"].each do |character|
        escaped = SimpleOAuth::Header.escape(character)

        assert_equal character, escaped
      end
    end

    def test_escape_escapes_non_ascii_characters
      assert_equal "%C3%A9", SimpleOAuth::Header.escape("é")
    end

    def test_escape_escapes_multibyte_characters
      assert_equal "%E3%81%82", SimpleOAuth::Header.escape("あ")
    end

    # .unescape tests

    def test_unescape_unescapes_percent_encoded_characters
      assert_equal "é", SimpleOAuth::Header.unescape("%C3%A9")
    end

    def test_unescape_unescapes_multibyte_characters
      assert_equal "あ", SimpleOAuth::Header.unescape("%E3%81%82")
    end

    def test_unescape_returns_unencoded_characters_as_is
      assert_equal "hello", SimpleOAuth::Header.unescape("hello")
    end

    def test_unescape_converts_non_string_to_string
      assert_equal "123", SimpleOAuth::Header.unescape(123)
    end

    def test_escape_converts_non_string_to_string
      assert_equal "123", SimpleOAuth::Header.escape(123)
    end
  end
end
