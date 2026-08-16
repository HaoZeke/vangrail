# frozen_string_literal: true

require_relative '../rail'

module Vangrail
  module Rails
    # Reads the parts of a page a human never sees.
    #
    # The largest measurement of indirect injection in the wild found roughly
    # seven in ten instances sitting in non-rendered HTML: comments, meta tags,
    # attributes, elements styled invisible. That is the natural place to put
    # one. A visible paragraph telling an assistant to ignore its instructions
    # is a paragraph the page's own readers will notice and report; the same
    # sentence in an alt attribute is read by the model and by nobody else.
    #
    # So this rail does not judge text. It extracts the spans a reader cannot
    # see and hands each to the rails that already know what an injection looks
    # like:
    #
    #   Rails::Hidden.new(rails: [Rails::InjectedInstructions.new,
    #                             Rails::Jailbreak.new])
    #
    # Delegating rather than pattern-matching keeps one definition of "an
    # injection" in the codebase, and keeps this class about where text was
    # found rather than what it says. A hidden span with ordinary content in it
    # passes: pages carry meta descriptions and alt text for good reasons, and
    # a rail that objected to invisible text as such would reject most of the
    # web.
    #
    # Only useful where documents arrive as HTML. A retrieval step that
    # converts to markdown before storing has usually dropped most of these
    # carriers already, which is a reason to run this at the fetch boundary
    # rather than a reason to skip it: what the converter drops silently is
    # exactly what nobody is looking at.
    class Hidden < Rail
      # Each entry pulls the readable part out of one carrier. Order is
      # reporting order, so the named carrier is the first that matched rather
      # than the last.
      CARRIERS = {
        'comment' => /<!--(.*?)-->/m,
        'meta' => /<meta\b[^>]*?\bcontent\s*=\s*["']([^"']{12,})["'][^>]*>/i,
        'alt_text' => /<[^>]+\balt\s*=\s*["']([^"']{12,})["'][^>]*>/i,
        'title_attribute' => /<[^>]+\btitle\s*=\s*["']([^"']{12,})["'][^>]*>/i,
        'aria_label' => /<[^>]+\baria-label\s*=\s*["']([^"']{12,})["'][^>]*>/i,
        'data_attribute' => /<[^>]+\bdata-[\w-]+\s*=\s*["']([^"']{12,})["'][^>]*>/i,
        'script' => /<script\b[^>]*>(.*?)<\/script>/mi,
        'template' => /<(?:template|noscript)\b[^>]*>(.*?)<\/(?:template|noscript)>/mi,
        # An element that is present, rendered, and invisible. The three ways
        # that is written in a page an attacker controls: a display or
        # visibility rule, a zero size, and text the colour of its background.
        'invisible_style' => /
          <[^>]*\bstyle\s*=\s*["'][^"']*
          (?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|
             font-size\s*:\s*0|color\s*:\s*(?:\#f{3,6}|white|transparent))
          [^"']*["'][^>]*>(.*?)<\/
        /xmi,
        'hidden_attribute' => /<(\w+)\b[^>]*\bhidden\b[^>]*>(.*?)<\/\1>/mi,
        # Markdown carries two of its own: a link title, and image alt text.
        'link_title' => /\[[^\]]*\]\([^)\s]+\s+["']([^"']{12,})["']\)/,
        'image_alt' => /!\[([^\]]{12,})\]\(/,
      }.freeze

      attr_reader :rails, :carriers

      def initialize(rails:, carriers: CARRIERS, name: 'hidden', sides: [:context])
        super(name: name, sides: sides)
        @rails = Array(rails)
        @carriers = carriers
      end

      def offline?
        rails.all?(&:offline?)
      end

      def cache_key(text, _context)
        text if offline?
      end

      def decide(text, context)
        uncertain = nil
        spans(text).each do |carrier, span|
          rails.each do |rail|
            result = rail.call(span, context)
            if result.blocked?
              return block(categories: (result.categories || []) + ["hidden:#{carrier}"],
                           reason: "#{result.reason} (hidden in #{carrier.tr('_', ' ')})")
            end

            uncertain ||= result unless result.certain?
          end
        end
        return unchecked(uncertain.reason) if uncertain

        pass
      end

      # Every hidden span, labelled by where it came from. Public because an
      # application that rejected a page wants to show what was in it.
      def spans(text)
        body = text.to_s
        carriers.flat_map do |carrier, pattern|
          body.scan(pattern).filter_map do |match|
            span = Array(match).compact.max_by(&:length).to_s.strip
            [carrier, span] unless span.empty?
          end
        end
      end
    end
  end
end
