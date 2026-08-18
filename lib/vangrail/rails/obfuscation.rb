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
      # Characters with no rendered form, written as escapes: a table of
      # invisible characters spelled with invisible characters cannot be
      # reviewed, and this one is a security boundary.
      #
      # Four families and two stragglers:
      #
      #   separators      zero-width space and joiners, the word joiner, the
      #                   byte-order mark, the Mongolian vowel separator, the
      #                   soft hyphen, the combining grapheme joiner
      #   bidi controls   the trojan-source family, where the rendered order
      #                   and the stored order disagree
      #   invisible ops   invisible times, invisible function application, and
      #                   their neighbours, which carry meaning inside MathML
      #                   and none at all in prose
      #   tags            U+E0000-E007F, deprecated as language tags and now
      #                   the carrier with the most room in it: 128 code points
      #                   that render as nothing and map straight onto ASCII,
      #                   usually hung off one ordinary emoji so the visible
      #                   text is a single character long
      #
      # Two stragglers belong to no family. The replacement character is what a
      # scrub leaves where an invalid byte was, and the backspace is a control
      # character a terminal acts on rather than draws. Garbage bytes and a
      # backspace inside a keyword are a zero-width joiner with a cruder tool:
      # removing them restores the phrase. Legitimate text carries neither.
      INVISIBLE = Regexp.new(
        '[\\u{0008}\\u{00AD}\\u{034F}\\u{061C}\\u{180E}\\u{200B}-\\u{200F}' \
        '\\u{202A}-\\u{202E}\\u{2060}-\\u{206F}\\u{FEFF}\\u{FFFD}' \
        '\\u{E0000}-\\u{E007F}]'
      )

      # Variation selectors, which are the one invisible carrier with an honest
      # use: FE0F after an emoji base asks for the emoji presentation, and
      # stripping it would turn a warning sign into a dingbat on every page
      # that carries one.
      #
      # What has no honest use is two of them in a row. No base character takes
      # a second variation selector, and a payload needs one per byte, so the
      # run length separates the two cases without a threshold to tune. The
      # supplement is in here because the byte encoding needs 256 values and
      # the sixteen selectors in the BMP only give it sixteen.
      VARIATION_SELECTOR_RUN = /[\u{FE00}-\u{FE0F}\u{E0100}-\u{E01EF}]{2,}/

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

      def initialize(rails:, transforms: %i[invisible tags selectors confusables confusables_all
                                            rot13 base64 nfkc],
                     name: 'obfuscation', sides: %i[input context])
        super(name: name, sides: sides)
        @rails = Array(rails)
        @transforms = Array(transforms).map(&:to_sym)
      end

      # Every carrier removed, in one place, because the rewrite handed back to
      # the caller and the text the delegate rails read have to be the same
      # string. Public because a fetch boundary wants the scrub without the
      # rails: an invisible payload that never reaches the corpus cannot be
      # missed later by a reviewer reading a diff.
      def self.scrub(text)
        text.to_s.gsub(INVISIBLE, '').gsub(VARIATION_SELECTOR_RUN, '')
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
        stripped = self.class.scrub(body)

        hit, uncertain = first_objection(body, stripped, context)
        return hit if hit
        return unchecked(uncertain.reason) if uncertain

        return pass if stripped == body

        modify(stripped, categories: ['invisible_characters'],
                         reason: 'removed zero-width, bidi, or tag characters')
      end

      # Transforms whose input is the text as it arrived rather than the text with
      # its invisible characters removed, because for these two the invisible
      # characters carry the message.
      CARRIERS = %i[tags selectors].freeze

      # The decoded forms of a text, labelled. Public because an application
      # that logs a blocked page wants to show what it decoded to.
      def variants(text, only: nil, except: nil)
        body = text.to_s
        wanted = transforms
        wanted &= Array(only) if only
        wanted -= Array(except) if except
        wanted.filter_map do |name|
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
        # the transforms that undo an encoding of the visible text run after the
        # removal rather than instead of it.
        candidates << [:invisible, stripped] unless stripped == body
        # The carrier decoders are the exception, and it is not a small one: for
        # them the invisible characters are the payload rather than padding
        # around it, so they read the text as it arrived. Reading the stripped
        # text meant decoding a string from which the whole message had just been
        # deleted, and finding nothing every time.
        candidates.concat(variants(body, only: CARRIERS))
        candidates.concat(variants(stripped, except: CARRIERS))

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

          rewritten = rewrite_for(published, name, decoded, viewed)
          # A rewrite that cannot be put back on the page is not a rewrite. The
          # rail used to report `modified` and hand back the text unchanged, so a
          # caller reading `content_or` forwarded a credential while the record
          # beside it said the credential had been removed. Refusing is the only
          # honest answer: the sensitive text is there, in a form this rail cannot
          # neutralise, and passing it on is the one thing that must not happen.
          if rewritten.nil?
            result, extra, = variant_modified
            return [block(categories: (result.categories || []) + extra + ['unrewritable'],
                          reason: "#{result.reason}, and the rewrite could not be applied " \
                                  "to the text as written (hidden with #{name})"), nil]
          end

          published = rewritten
          modified = variant_modified
        end
        if modified
          result, extra, name = modified
          return [modify(published, categories: (result.categories || []) + extra,
                         reason: reason_for(name, result),
                         certain: result.certain? && uncertain.nil?), nil]
        end

        [nil, uncertain]
      end

      # What the reader is told. For a carrier the rail did not edit the visible
      # text at all: it removed an invisible payload, and what the payload said is
      # why. Saying "redacted a credential" over an untouched page would name the
      # wrong operation.
      def reason_for(name, result)
        return "#{result.reason} (hidden with #{name})" unless CARRIERS.include?(name)

        "removed an invisible payload, which carried: #{result.reason} (#{name})"
      end

      # The page with the child's rewrite on it, or nil when there is no faithful
      # way to put it there.
      def rewrite_for(published, name, decoded, rewrite)
        # A carrier payload is not in the visible text, so there is nothing to
        # splice and the strip has already removed it. Splicing anyway deleted
        # real page text whenever the payload happened to be as long as the page:
        # "Quota is 200 GB on the home filesystem." came back as "Quota
        # is[redacted]system.", and the payload's length is the attacker's choice.
        return published if CARRIERS.include?(name)

        candidate = apply_rewrite(published, name, decoded, rewrite)
        return nil if candidate == published && rewrite != decoded

        # Verified rather than assumed. The splice heuristics work on lengths and
        # substrings, and a rewrite that lands in the wrong place leaves the thing
        # it was supposed to remove exactly where it was.
        neutralised?(candidate, name) ? candidate : nil
      end

      # Does the objection survive the rewrite. Same transform, same rails: if a
      # child still objects to the decoded form of the candidate, the rewrite did
      # not do its job.
      def neutralised?(candidate, name)
        decoded = apply(name, candidate) || candidate
        rails.none? { |rail| rail.call(decoded, side: :context).blocked? } &&
          rails.none? { |rail| rail.call(decoded, side: :context).modified? }
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
        when :invisible then self.class.scrub(body)
        when :tags then decode_tags(body)
        when :selectors then decode_selectors(body)
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
      # The tags block, read as the ASCII it encodes. U+E0000 plus n is code point
      # n, which is the whole scheme: 128 code points that render as nothing and
      # spell a sentence directly.
      #
      # The strip already denies the attack, since the payload never reaches a
      # model. What this buys is a report that names the injection rather than a
      # rewrite naming a character class, which is the difference between a page
      # somebody looks at and a page nobody does. `kb/` is scraped, and a page
      # that smuggled an instruction once will do it again.
      TAGS = /[\u{E0000}-\u{E007F}]{4,}/

      def decode_tags(body)
        decode_runs(body, TAGS) { |c| c.ord - 0xE0000 }
      end

      # Variation selectors, read as the bytes they carry: FE00 to FE0F for 0x00
      # to 0x0F and the supplement for the rest. Four or more, because a payload
      # is a run and two or three selectors carry nothing worth reading.
      #
      # This is also the encoding Vangrail::Watermark uses on the way out, so a
      # marked answer pasted back in as a question decodes to eleven bytes of
      # HMAC. Those are not printable text, and the printability test below drops
      # them: the disclosure mark is not an injection and must not be reported as
      # one.
      SELECTORS = /[\u{FE00}-\u{FE0F}\u{E0100}-\u{E01EF}]{4,}/

      def decode_selectors(body)
        decode_runs(body, SELECTORS) do |c|
          cp = c.ord
          cp < 0xE0100 ? cp - 0xFE00 : (cp - 0xE0100) + 0x10
        end
      end

      # Each run turned into bytes and kept only if it reads as text. A run that
      # decodes to a key, a hash, or a truncated payload contributes nothing and
      # would otherwise hand a rail a string of control characters to judge.
      def decode_runs(body, pattern)
        pieces = body.scan(pattern).filter_map do |run|
          bytes = run.each_char.map { |c| yield(c) }
          next if bytes.any? { |b| b.negative? || b > 0xFF }

          readable_bytes(bytes)
        end
        pieces.empty? ? nil : pieces.join("\n")
      end

      # Control bytes a payload cannot be read through, dropped rather than used as
      # a reason to give up on the run. One U+E0000 in front of an ASCII payload
      # decodes to a leading NUL, and rejecting the whole run for it turned a
      # block into a rewrite: the injection was still in the page and the report
      # named a character class. A prefix byte is the attacker's cheapest move and
      # it must not be the one that works.
      UNREADABLE = "\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F"

      # At least this many readable characters. Below it a decode is noise, and a
      # rail reading four characters reports on noise.
      MIN_PAYLOAD = 8

      def readable_bytes(bytes)
        text = bytes.pack('C*').force_encoding(Encoding::UTF_8)
        return nil unless text.valid_encoding?

        text = text.delete(UNREADABLE)
        return nil if text.strip.empty?
        return nil if text.count("^ -~\n\t").positive?
        return nil if text.length < MIN_PAYLOAD

        text
      end

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
