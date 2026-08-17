# frozen_string_literal: true

require_relative '../confusables'
require_relative '../rail'

module Vangrail
  module Rails
    # Runs other rails again over the text an attacker actually meant.
    #
    # Every pattern rail reads what is written. An attacker who knows that
    # writes it differently: base64 the paragraph and ask the model to decode
    # it, rot13 it, spell it with Cyrillic letters that look like Latin ones,
    # put zero-width joiners between the letters of "ignore", or set a
    # right-to-left override so the rendered page and the byte sequence say
    # different things. The model reads through all of it, because that is what
    # models do, and the regexps see nothing.
    #
    # The answer is not more patterns. It is to undo the encoding and run the
    # rails that already exist over the result, which is why this takes a rail
    # list rather than defining checks of its own:
    #
    #   Rails::Obfuscation.new(rails: [Rails::InjectedInstructions.new,
    #                                  Rails::Jailbreak.new])
    #
    # Each transform is applied on its own, and a variant identical to the
    # original is dropped, so ordinary text costs one comparison per transform
    # and nothing else. A hit names both the rail and the encoding it was
    # hiding under, because "blocked" without that is unactionable for whoever
    # has to look at the page. A child that rewrites a variant (a key inside a
    # decoded blob) is spliced back into the page, or into that variant when
    # the variant *is* the page (the invisible-character strip). The decoded
    # form is not published in place of the document.
    #
    # Invisible characters are handled here directly rather than by a delegate:
    # they are stripped, and the strip is reported as a rewrite. A zero-width
    # joiner inside a word has no honest use in a handbook, and removing it
    # costs a reader nothing while denying the cheapest bypass there is.
    #
    # What this does not do is guess. There is no scoring, no entropy
    # threshold, no "this looks encoded" heuristic that would fire on the base64
    # blobs and hashes a cluster handbook is full of. A blob either decodes to
    # text a rail objects to, or it does not.
    class Obfuscation < Rail
      # Zero-width and bidi control characters. The first four are the invisible
      # separators; the bidi set is the trojan-source family, where the rendered
      # order and the stored order disagree.
      # The last one is the replacement character, which is what a scrub leaves
      # where an invalid byte was. Garbage bytes inside a keyword are the same
      # move as a zero-width joiner with a cruder tool: they break a pattern
      # without changing what a model reads, and scrubbing restores validity
      # rather than the phrase. Legitimate text does not carry them.
      INVISIBLE = /[\u200B-\u200D\u2060\uFEFF\u180E\u202A-\u202E\u2066-\u2069\uFFFD\u00AD\u0008]/

      # A base64 run long enough to hold a sentence. Below this the decode is
      # noise, and a handbook is full of short tokens that happen to be in the
      # alphabet.
      #
      # Bounded by lookaround rather than \b, because + and / are not word
      # characters: a blob ending in one had its last character trimmed off the
      # match, and a base64 string one character short decodes to a sentence
      # with its tail missing. That cost the corpus a case, and the case it
      # cost was an HTML comment, whose pattern needs the closing marker.
      BASE64 = /(?<![A-Za-z0-9+\/=])[A-Za-z0-9+\/]{24,}={0,2}(?![A-Za-z0-9+\/=])/

      attr_reader :rails, :transforms

      def initialize(rails:, transforms: %i[invisible confusables confusables_all rot13 base64 nfkc],
                     name: 'obfuscation', sides: %i[input context])
        super(name: name, sides: sides)
        @rails = Array(rails)
        @transforms = Array(transforms).map(&:to_sym)
      end

      # Only if everything it delegates to is. A wrapper around a model rail
      # inherits the model rail's posture.
      def offline?
        rails.all?(&:offline?)
      end

      def cache_key(text, _context)
        text if offline?
      end

      def decide(text, context)
        body = text.to_s
        stripped = body.gsub(INVISIBLE, '')

        hit, uncertain = first_objection(body, stripped, context)
        return hit if hit
        return unchecked(uncertain.reason) if uncertain

        return pass if stripped == body

        modify(stripped, categories: ['invisible_characters'],
                         reason: 'removed zero-width or bidi control characters')
      end

      # The decoded forms of a text, labelled. Public because an application
      # that logs a blocked page wants to show what it decoded to.
      def variants(text)
        body = text.to_s
        transforms.filter_map do |name|
          decoded = apply(name, body)
          next if decoded.nil? || decoded == body || decoded.strip.empty?

          [name, decoded]
        end
      end

      private

      # Walks every variant. A block stops the pass. A rewrite is spliced into
      # the page and the remaining encodings are still read, so a redaction
      # cannot hide a later injection.
      def first_objection(body, stripped, context)
        candidates = []
        # The stripped text is a variant in its own right when anything was
        # removed: "i<zwj>gnore previous instructions" is the whole attack, and
        # every other transform runs after the removal rather than instead of it.
        candidates << [:invisible, stripped] unless stripped == body
        candidates.concat(variants(stripped))

        published = stripped
        modified = nil
        uncertain = nil
        candidates.each do |name, decoded|
          viewed = decoded
          variant_modified = nil
          extra = ["encoded:#{name}"]
          rails.each do |rail|
            result = rail.call(viewed, context)
            if result.blocked?
              return [block(categories: (result.categories || []) + extra,
                            reason: "#{result.reason} (hidden with #{name})"), nil]
            end
            if result.modified?
              viewed = result.content.to_s
              variant_modified = [result, extra, name]
              uncertain ||= result unless result.certain?
            elsif !result.certain?
              uncertain ||= result
            end
          end
          next if variant_modified.nil? || modified

          published = apply_rewrite(published, name, decoded, viewed)
          modified = variant_modified
        end
        if modified
          result, extra, name = modified
          return [modify(published, categories: (result.categories || []) + extra,
                         reason: "#{result.reason} (hidden with #{name})",
                         certain: result.certain? && uncertain.nil?), nil]
        end

        [nil, uncertain]
      end

      # Puts the child's rewrite back on the page the reader will see.
      def apply_rewrite(published, name, decoded, rewrite)
        return splice_base64(published, rewrite) if name == :base64
        return rewrite if decoded == published
        return published.sub(decoded) { rewrite } if published.include?(decoded)
        return splice_aligned(published, decoded, rewrite) if published.length == decoded.length

        published
      end

      def splice_base64(published, rewrite)
        runs = published.scan(BASE64)
        return published if runs.empty?
        return published.sub(runs.first) { rewrite } unless runs.size > 1

        pieces = rewrite.split("\n")
        return published.sub(runs.first) { rewrite } unless pieces.size == runs.size

        runs.zip(pieces).reduce(published) { |acc, (run, piece)| acc.sub(run) { piece } }
      end

      def splice_aligned(published, decoded, rewrite)
        prefix = 0
        limit = [decoded.length, rewrite.length].min
        prefix += 1 while prefix < limit && decoded[prefix] == rewrite[prefix]

        suffix = 0
        max_suffix = [decoded.length - prefix, rewrite.length - prefix].min
        while suffix < max_suffix &&
              decoded[decoded.length - 1 - suffix] == rewrite[rewrite.length - 1 - suffix]
          suffix += 1
        end

        replacement = rewrite[prefix, rewrite.length - prefix - suffix]
        published[0, prefix] + replacement.to_s + published[published.length - suffix, suffix]
      end

      def apply(name, body)
        case name
        when :invisible then body.gsub(INVISIBLE, '')
        when :confusables then defold(body)
        when :confusables_all then Confusables.fold_all(body)
        when :rot13 then body.tr('A-Za-z', 'N-ZA-Mn-za-m')
        when :base64 then decode_base64(body)
        when :nfkc then normalise(body)
        end
      end

      # Two readings of the same text, because the policies fail in opposite
      # directions and a variant costs one comparison.
      #
      # :confusables folds only words that mix ASCII with imitators, which is
      # what an imitation attack looks like and what leaves a page of Russian
      # alone. It misses a word converted character for character, where
      # nothing ASCII is left to mix with.
      #
      # :confusables_all folds everything and catches that, at the price of
      # turning genuine Cyrillic into noise. The noise is never shown to
      # anybody: a variant exists to be read by a pattern, and the corpus
      # asserts that ordinary non-Latin prose does not match one.
      def defold(body)
        Confusables.fold(body)
      end

      # Every long base64 run in the text, decoded and joined. A run that is not
      # valid base64, or that decodes to bytes rather than text, contributes
      # nothing rather than failing the whole pass: a handbook page carrying one
      # hash and one payload should still have the payload read.
      def decode_base64(body)
        pieces = body.scan(BASE64).filter_map { |run| readable(run) }
        pieces.empty? ? nil : pieces.join("\n")
      end

      def readable(run)
        decoded = run.unpack1('m')
        return nil if decoded.nil? || decoded.empty?

        decoded.force_encoding(Encoding::UTF_8)
        return nil unless decoded.valid_encoding?
        # Printable enough to be a sentence rather than a compressed blob.
        return nil if decoded.count("^ -~\n\t").positive?

        decoded
      rescue ArgumentError
        nil
      end

      # Compatibility normalisation folds the fullwidth and mathematical
      # alphabets, which is the other cheap way to write a word a regexp will
      # not recognise.
      def normalise(body)
        body.unicode_normalize(:nfkc)
      rescue ArgumentError, Encoding::CompatibilityError
        nil
      end
    end
  end
end
