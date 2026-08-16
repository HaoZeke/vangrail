# frozen_string_literal: true

require_relative '../rail'

module Vangrail
  module Rails
    # Redacts credentials, returning :modified rather than blocking.
    #
    # This is the rail that justifies having three statuses. An answer that
    # quotes a config file with a live token is a useful answer with one bad
    # span in it: blocking it throws away the help, and passing it leaks the
    # token. Replacing the span keeps both halves honest, and the caller can see
    # from the status that what it is about to show has been edited.
    #
    # Patterns cover shapes that are unambiguous on sight. Anything needing
    # judgement belongs in a policy rail, not here: a false positive silently
    # corrupts an answer, which is worse than a missed match a later rail can
    # still catch.
    class Secrets < Rail
      PLACEHOLDER = '[redacted]'

      DEFAULT_PATTERNS = {
        'private_key' => /-----BEGIN[A-Z ]*PRIVATE KEY-----.*?-----END[A-Z ]*PRIVATE KEY-----/m,
        'openai_key' => /\bsk-[A-Za-z0-9_-]{20,}\b/,
        'anthropic_key' => /\bsk-ant-[A-Za-z0-9_-]{20,}\b/,
        'github_token' => /\bgh[pousr]_[A-Za-z0-9]{30,}\b/,
        'slack_token' => /\bxox[abposr]-[A-Za-z0-9-]{10,}\b/,
        'aws_access_key' => /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/,
        'jwt' => /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/,
        'bearer_header' => /\b(?i:authorization)\s*:\s*(?i:bearer)\s+\S{12,}/,
        'inline_password' => /\b(?i:password|passwd|api[_-]?key|secret)\s*[=:]\s*(?!\[redacted\])\S{6,}/
      }.freeze

      attr_reader :patterns, :placeholder

      def initialize(patterns: DEFAULT_PATTERNS, placeholder: PLACEHOLDER, name: 'secrets',
                     sides: [:output])
        super(name: name, sides: sides)
        @patterns = patterns
        @placeholder = placeholder
      end

      def language_agnostic?
        true
      end

      def cache_key(text, _context)
        text
      end

      def decide(text, _context)
        body = text.to_s
        found = []
        redacted = patterns.reduce(body) do |acc, (label, pattern)|
          acc.gsub(pattern) do |match|
            found << label
            replacement(label, match)
          end
        end
        return pass if found.empty?

        modify(redacted, categories: found.uniq, reason: "redacted #{found.uniq.join(', ')}")
      end

      private

      # Keeps the key name visible so the reader still learns which setting the
      # answer was talking about, and loses only the value.
      def replacement(label, match)
        return "#{match[/\A[^=:]*[=:]\s*/]}#{placeholder}" if label == 'inline_password'
        return "#{match[/\A\S+\s*:\s*\S+\s/]}#{placeholder}" if label == 'bearer_header' && match =~ /\s/

        placeholder
      end
    end
  end
end
