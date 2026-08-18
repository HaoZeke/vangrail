# frozen_string_literal: true

require 'openssl'

module Vangrail
  # A machine-readable mark saying text was generated, carried in the text
  # itself.
  #
  # Article 50(2) of the AI Act requires providers of generative systems to mark
  # their output in a machine-readable format, detectable as artificially
  # generated, by solutions that are effective, interoperable, robust and
  # reliable as far as technically feasible. Article 50(4) puts a matching
  # disclosure duty on whoever publishes such text to inform the public. The
  # first is a property of the bytes and belongs here. The second is a sentence
  # a reader can see and belongs in the application's page.
  #
  # None of the sampler-side schemes can do this job for us. A green-list tilt
  # (doi:10.48550/arXiv.2301.10226), SynthID's tournament sampling, and the
  # Aaronson construction all live inside token selection, and an application
  # holding a key for somebody else's endpoint does not get to touch it. Under
  # bring-your-own-key it is not even one endpoint. What the application does
  # own is the text after it arrives, so the mark goes there: deterministic,
  # identical for every model, and unaffected by which provider answered.
  #
  # Asking the model to sign its own output is the other non-answer. It fails on
  # exactly the cases the obligation is about: a small model, a long context, a
  # terse-output instruction, a provider that trims trailing lines.
  #
  # == The format
  #
  # Eleven bytes per marked segment, encoded one byte per variation selector and
  # appended to the segment's last character:
  #
  #   0-1  MAGIC, 0xA1 0x50, public and fixed
  #   2    VERSION, currently 1
  #   3-10 TAG, HMAC-SHA256 truncated to eight bytes, or eight zero bytes
  #
  # Variation selectors carry a byte each: 0x00 to 0x0F as U+FE00 to U+FE0F, and
  # 0x10 to 0xFF as U+E0100 to U+E01EF. They render as nothing after a base
  # character that has no variant form, they survive a copy through a browser, an
  # editor, and a mail client that keeps Unicode, and Rails::Obfuscation leaves a
  # run of them alone on the output side.
  #
  # Two levels of reading, which is the point of splitting magic from tag:
  #
  #   anybody      finds MAGIC and VERSION and knows the text is generated. No
  #                key, no agreement with us, eleven lines of code against the
  #                published layout. That is what interoperable has to mean.
  #   the issuer   recomputes the HMAC and knows the text is theirs, and that
  #                the mark was not lifted off another answer and pasted on.
  #
  # The tag covers the segment it is attached to, canonicalised: marks removed,
  # whitespace runs collapsed, ends trimmed. So a mail client that rewraps the
  # paragraph still verifies, quoting one paragraph out of six still verifies on
  # that paragraph, and moving a mark onto different words does not.
  #
  # == What it does not survive
  #
  # Retyping, a transcription, an ASCII-only pipeline, or any tool that strips
  # format characters. There is no text mark that survives those and no scheme
  # that claims otherwise, which is why the Article 50(4) sentence is visible
  # and this is not the whole answer to provenance on its own.
  #
  # Code is never marked. A variation selector inside a shell command is a
  # command that fails, or worse, one that runs differently, so fenced and
  # indented blocks come back byte for byte.
  module Watermark
    MAGIC = [0xA1, 0x50].freeze
    VERSION = 1
    TAG_BYTES = 8
    UNSIGNED = [0].freeze * TAG_BYTES
    LENGTH = MAGIC.length + 1 + TAG_BYTES

    # The domain string keeps this HMAC from ever matching one computed for
    # another purpose with the same key.
    DOMAIN = 'vangrail/watermark/v1'

    # One byte per selector. Sixteen in the BMP and the rest in the supplement,
    # because a byte needs 256 values.
    LOW = 0xFE00
    HIGH = 0xE0100
    SELECTOR = /[\u{FE00}-\u{FE0F}\u{E0100}-\u{E01EF}]+/

    # A fence, or four spaces at the start of a line. Both are code, and code is
    # copied into a terminal.
    FENCE = /^[ \t]*(?:```|~~~)/
    INDENTED = /^(?: {4}|\t)/

    module_function

    # The marked text. Idempotent: a segment that already carries a valid mark
    # for this key is left as it is, so a rail can run twice without stacking
    # selectors.
    def mark(text, key: nil, issuer: nil)
      map_segments(text.to_s) do |segment|
        stripped = strip(segment)
        next segment if stripped.strip.empty?
        next segment if authentic_segment?(segment, key: key, issuer: issuer)

        selectors = encode(payload(stripped, key: key, issuer: issuer))
        # Before the trailing newline, not after it: a selector run needs a base
        # character in front of it or a renderer draws a dotted box for it.
        stripped.sub(/(\s*)\z/) { "#{selectors}#{::Regexp.last_match(1)}" }
      end
    end

    # Every mark removed, and nothing else touched.
    def strip(text)
      text.to_s.gsub(SELECTOR) do |run|
        kept = decode(run).reject { |bytes| bytes[0, MAGIC.length] == MAGIC }
        kept.map { |bytes| encode(bytes) }.join
      end
    end

    # Is this text marked as generated. No key, because that is the question the
    # obligation is about: anybody holding the text can ask it.
    def marked?(text)
      marks(text).any?
    end

    # Every mark found, as { version:, tag: }, in the order they appear.
    def marks(text)
      text.to_s.scan(SELECTOR).flat_map { |run| decode(run) }
          .filter_map do |bytes|
        next unless bytes[0, MAGIC.length] == MAGIC

        { version: bytes[MAGIC.length], tag: bytes[(MAGIC.length + 1)..] }
      end
    end

    # Per segment: marked, and if a key was given, ours.
    #
    #   report = Vangrail::Watermark.verify(answer, key: ENV['ASK_WATERMARK_KEY'])
    #   report.marked?      # something in here says generated
    #   report.authentic?   # and at least one mark is this issuer's
    #   report.coverage     # share of segments carrying our mark
    def verify(text, key: nil, issuer: nil)
      segments = segments(text.to_s).reject { |segment| strip(segment).strip.empty? }
      rows = segments.map do |segment|
        { text: strip(segment),
          marked: marked?(segment),
          authentic: !key.nil? && authentic_segment?(segment, key: key, issuer: issuer) }
      end
      Report.new(rows)
    end

    # What verify found. Plain readers rather than predicates on a hash, because
    # a caller reporting a posture reads all three.
    class Report
      attr_reader :segments

      def initialize(segments)
        @segments = segments.freeze
      end

      def marked?
        segments.any? { |s| s[:marked] }
      end

      def authentic?
        segments.any? { |s| s[:authentic] }
      end

      # Share of segments carrying our mark, 0.0 to 1.0. A quote of one
      # paragraph out of six scores low and is still ours; the number is for
      # deciding whether a whole answer or a fragment is in front of you.
      def coverage
        return 0.0 if segments.empty?

        segments.count { |s| s[:authentic] }.fdiv(segments.length)
      end

      def to_h
        { marked: marked?, authentic: authentic?, coverage: coverage,
          segments: segments.length }
      end
    end

    # --- the codec ---

    # Bytes to selectors.
    def encode(bytes)
      bytes.map { |b| [b < 0x10 ? LOW + b : HIGH + (b - 0x10)].pack('U') }.join
    end

    # A run of selectors back to the byte strings in it, split on MAGIC so a
    # segment carrying two marks reports two.
    def decode(run)
      bytes = run.each_char.map do |c|
        cp = c.ord
        cp < HIGH ? cp - LOW : (cp - HIGH) + 0x10
      end
      split_on_magic(bytes)
    end

    def split_on_magic(bytes)
      out = []
      index = 0
      while index < bytes.length
        if bytes[index, MAGIC.length] == MAGIC && bytes.length - index >= LENGTH
          out << bytes[index, LENGTH]
          index += LENGTH
        else
          out << [bytes[index]]
          index += 1
        end
      end
      out
    end

    def payload(canonical_source, key: nil, issuer: nil)
      MAGIC + [VERSION] + tag(canonical_source, key: key, issuer: issuer)
    end

    def tag(text, key: nil, issuer: nil)
      return UNSIGNED.dup if key.nil? || key.to_s.empty?

      message = "#{DOMAIN}\n#{issuer}\n#{canonical(text)}"
      OpenSSL::HMAC.digest('SHA256', key.to_s, message).bytes[0, TAG_BYTES]
    end

    # What the tag is computed over. Rewrapping a paragraph must not break a
    # verification, and neither must a trailing space a renderer added.
    def canonical(text)
      strip(text).gsub(/\s+/, ' ').strip
    end

    def authentic_segment?(segment, key: nil, issuer: nil)
      return false if key.nil? || key.to_s.empty?

      wanted = tag(strip(segment), key: key, issuer: issuer)
      marks(segment).any? { |m| m[:version] == VERSION && m[:tag] == wanted }
    end

    # --- segmentation ---

    # Paragraphs, with fenced and indented code kept whole and left alone. The
    # separators stay in the list so a round trip through map_segments returns
    # the original spacing.
    def segments(text)
      text.split(/(\n[ \t]*\n)/)
    end

    def map_segments(text)
      in_fence = false
      segments(text).map do |segment|
        fences = segment.scan(FENCE).length
        was_open = in_fence
        in_fence = fences.odd? ? !in_fence : in_fence
        next segment if was_open || fences.positive?
        next segment if segment.match?(/\A\s*\z/) || segment.match?(INDENTED)

        yield segment
      end.join
    end
  end
end
