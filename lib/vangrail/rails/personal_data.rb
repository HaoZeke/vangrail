# frozen_string_literal: true

require_relative '../rail'

module Vangrail
  module Rails
    # Redacts a reader's own details before the question leaves the building.
    #
    # This is a privacy rail rather than a security one, and it exists because
    # of where the text goes next. A question typed into a documentation desk
    # is about to be sent to a model endpoint, which may be a third party, may
    # log, and may sit in another jurisdiction. A reader pasting a support
    # thread into it has not thought about any of that, and nothing in the
    # answer needs their phone number.
    #
    # Redacts rather than blocks, for the same reason the secrets rail does: the
    # question is answerable, and one span in it should not have been sent.
    #
    # The hard part on a cluster desk is not detection. It is that
    # `ssh rgoswami@snellius.example.org` is an email address by every
    # syntactic measure, and redacting it destroys the answer to the most
    # commonly asked question there is. So an address is left alone when it is
    # inside backticks or a fence, when its line carries a command that takes a
    # user@host argument or an ssh config keyword, or when a remote path
    # follows it. All three are in the corpus, because a rail that eats login
    # examples is worse for a handbook than no rail at all.
    #
    # National identity numbers are matched only beside their own name, and the
    # reason is the same false-positive budget. The Dutch BSN is nine digits
    # with a checksum that one number in eleven passes by accident, so a rail
    # reading bare nine-digit runs redacts job ids and project numbers out of
    # cluster questions, which makes it unusable.
    #
    # A label changes that trade completely. "Mijn BSN is 123456782" carries
    # the word and the checksum, and nothing on a cluster desk writes both by
    # accident; a bare 123456782 keeps passing through untouched. It is the
    # same pair-of-signals rule the rest of this gem uses, and it is what makes
    # the most sensitive identifier a Dutch reader can paste into a support
    # question something this rail can actually catch.
    class PersonalData < Rail
      PLACEHOLDER = '[redacted]'

      # Commands whose argument is a login target rather than a mailbox. Read
      # over the line rather than the character before the match: scp puts a
      # source path in between, and an ssh config line has no command on it at
      # all, only the User keyword.
      HOST_COMMANDS = /\b(?:ssh|scp|sftp|rsync|mosh|ssh-copy-id|ssh:\/\/|sftp:\/\/|User)\b/i

      # The other half of scp and rsync syntax: an address followed by a remote
      # path is a target, not a mailbox.
      REMOTE_PATH = /\A:[~\/\w.]/

      # Local parts that are documentation rather than a person.
      PLACEHOLDER_USERS = /\A(?:user|username|your[._-]?name|login|account|me|example|
                              firstname|lastname|name|admin|root)\z/xi

      PATTERNS = {
        'email' => /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/,
        # International or national, with a separator, long enough to be a
        # phone number and not a job id: a leading + or 00, or a leading zero
        # with grouping.
        'phone' => /(?:\+|\b00)[1-9]\d{0,2}[\s.-]?(?:\(?\d{1,4}\)?[\s.-]?){2,5}\d{2,4}\b
                    |\b0\d{1,3}[\s.-]\d{3}[\s.-]?\d{3,4}\b/x,
        'iban' => /\b[A-Z]{2}\d{2}\s?(?:[A-Z0-9]{4}\s?){2,7}[A-Z0-9]{1,4}\b/,
        # Separators between the digits rather than after them: the trailing
        # form eats the space before the next word and redacts it away.
        'card' => /\b\d(?:[ -]?\d){12,18}\b/,
        # The number beside its own name, in the words a Dutch reader uses for
        # it. The digits may carry the dots or spaces a form prints them with.
        'bsn' => /\b(?:bsn|burgerservicenummer|sofinummer|sofi[\s-]?nummer)\b
                  [^\n]{0,24}?((?:\d[\s.-]?){8}\d)\b/xi,
      }.freeze

      attr_reader :patterns, :placeholder

      def initialize(patterns: PATTERNS, placeholder: PLACEHOLDER,
                     name: 'personal_data', sides: [:input])
        super(name: name, sides: sides)
        @patterns = patterns
        @placeholder = placeholder
      end

      def offline?
        true
      end

      def cache_key(text, _context)
        text
      end

      def call(text, _context)
        body = text.to_s
        found = []
        redacted = patterns.reduce(body) do |acc, (label, pattern)|
          replace(acc, label, pattern, found)
        end
        return pass if found.empty?

        modify(redacted, categories: found.uniq,
                         reason: "redacted #{found.uniq.join(', ')} before sending")
      end

      private

      def replace(body, label, pattern, found)
        body.gsub(pattern) do |match|
          m = Regexp.last_match
          next match unless redact?(label, match, m.pre_match, m.post_match)

          found << label
          # Where the pattern had to read a label to be sure, only the value
          # goes. The reader still sees what the desk was told about, the same
          # way the secrets rail keeps the setting name and loses the key.
          m[1] ? match.sub(m[1], placeholder) : placeholder
        end
      end

      def redact?(label, match, before, after)
        return false if in_code?(before)

        case label
        when 'email' then mailbox?(match, before, after)
        when 'card' then card?(match)
        when 'bsn' then bsn?(match)
        else true
        end
      end

      # An address is a mailbox unless it is a login target or a placeholder in
      # documentation.
      def mailbox?(match, before, after)
        return false if after.match?(REMOTE_PATH)
        return false if before[/[^\n]*\z/].match?(HOST_COMMANDS)

        !match.split('@').first.match?(PLACEHOLDER_USERS)
      end

      # Digits alone are not a card number. A cluster question is full of long
      # numbers, so the check has to be the one the issuers use.
      def card?(match)
        digits = match.gsub(/\D/, '')
        return false unless digits.length.between?(13, 19)

        luhn?(digits)
      end

      # The elfproef, which is the check the Dutch government applies: the nine
      # digits weighted 9 down to 2, with the last subtracted rather than
      # added, and the total divisible by eleven. Nine identical digits pass it
      # arithmetically and are a placeholder rather than a person, so they do
      # not count.
      def bsn?(match)
        digits = match.gsub(/\D/, '')
        return false unless digits.length == 9
        return false if digits.chars.uniq.size == 1

        weights = [9, 8, 7, 6, 5, 4, 3, 2, -1]
        total = digits.chars.each_with_index.sum { |c, i| c.to_i * weights[i] }
        (total % 11).zero?
      end

      def luhn?(digits)
        sum = digits.reverse.chars.each_with_index.sum do |c, i|
          n = c.to_i
          next n if i.even?

          n * 2 > 9 ? (n * 2) - 9 : n * 2
        end
        (sum % 10).zero?
      end

      # Inside backticks or a fence, the text is a command rather than a
      # person's details, and rewriting a command is how a guardrail becomes
      # the thing the reader has to work around.
      def in_code?(before)
        before.count('`').odd? || fenced?(before)
      end

      def fenced?(before)
        before.scan(/^```/).size.odd?
      end
    end
  end
end
