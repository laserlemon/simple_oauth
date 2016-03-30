require 'helper'
require 'simple_oauth/signatures'

class Test
  include Signatures::Base
end

RSpec.describe Signatures::Base do
  subject { Test.new }

  describe 'digest' do
    it 'raise exception' do
      expect { subject.send :digest, nil, nil }.to raise_error NotImplementedError
    end
  end

  describe '#secret' do
    before { allow(subject).to receive(:digest).and_return '' }

    it 'combines the consumer and token secrets with an ampersand' do
      subject.create('CONSUMER_SECRET', 'TOKEN_SECRET', 'ANY')
      expect(subject.send :secret).to eq 'CONSUMER_SECRET&TOKEN_SECRET'
    end

    it 'URI encodes each secret value before combination' do
      subject.create('CONSUM#R_SECRET', 'TOKEN_S#CRET', 'ANY')
      expect(subject.send :secret).to eq 'CONSUM%23R_SECRET&TOKEN_S%23CRET'
    end
  end

  describe '#escape' do
    before { allow(subject).to receive(:digest).and_return '' }

    it 'escapes (most) non-word characters' do
      [' ', '!', '@', '#', '$', '%', '^', '&'].each do |character|
        escaped = subject.escape(character)
        expect(escaped).not_to eq character
        expect(escaped).to eq uri_parser.escape(character, /.*/)
      end
    end

    it 'does not escape - . or ~' do
      ['-', '.', '~'].each do |character|
        escaped = subject.escape(character)
        expect(escaped).to eq character
      end
    end

    def self.test_special_characters
      it 'escapes non-ASCII characters' do
        expect(subject.escape('é')).to eq '%C3%A9'
      end

      it 'escapes multibyte characters' do
        expect(subject.escape('あ')).to eq '%E3%81%82'
      end
    end

    if RUBY_VERSION >= '1.9'
      test_special_characters
    else
      %w(n N e E s S u U).each do |kcode|
        describe %(when $KCODE = "#{kcode}") do
          original_kcode = $KCODE # rubocop:disable GlobalVars
          begin
            $KCODE = kcode # rubocop:disable GlobalVars
            test_special_characters
          ensure
            $KCODE = original_kcode # rubocop:disable GlobalVars
          end
        end
      end
    end
  end
end
