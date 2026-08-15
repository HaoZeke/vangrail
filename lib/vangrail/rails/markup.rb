# frozen_string_literal: true

require_relative '../rail'

module Vangrail
  module Rails
    # Removes markup that does something when the answer is rendered.
    #
    # An answer is text until a client renders it, and most clients render
    # markdown by pulling in a library that passes raw HTML straight through.
    # At that point a script tag in the answer is a script tag in the page, and
    # the model wrote it because a retrieved document told it to. That is a
    # cross-site scripting bug with a language model in the middle of it, and
    # the fact that the model is the delivery mechanism does not make it a
    # different class of bug.
    #
    # The application's own sanitiser is the real defence and this does not
    # replace it. What this covers is the case where there is no sanitiser,
    # which is most of them, and where the answer is passed to a renderer that
    # was chosen for how its tables look.
    #
    # Removes rather than blocks. An answer with a script tag in it is an answer
    # with one bad span, the same as an answer with a credential in it.
    #
    # Not on by default. A desk whose client renders markdown as text, or which
    # escapes before rendering, does not need it, and a rail that strips markup
    # nobody was going to execute is noise in the result.
    class Markup < Rail
      PATTERNS = {
        # Executes on load.
        'script' => /<script\b[^>]*>.*?<\/script>|<script\b[^>]*\/?>/mi,
        # Loads and executes something else.
        'frame' => /<(?:iframe|frame|embed|object|applet)\b[^>]*>(?:.*?<\/(?:iframe|frame|embed|object|applet)>)?/mi,
        # Runs on an event, which is how a lone img tag becomes an exploit.
        'event_handler' => /\son[a-z]{3,20}\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/i,
        # A scheme that executes rather than fetches.
        'active_scheme' => /(?:javascript|vbscript|data)\s*:\s*[^\s"'<>)]+/i,
        # Rewrites where a form or a link goes, or what the page loads next.
        'meta_refresh' => /<meta\b[^>]*http-equiv\s*=\s*["']?refresh["']?[^>]*>/i,
        'base_tag' => /<base\b[^>]*>/i,
        'form' => /<form\b[^>]*>.*?<\/form>|<form\b[^>]*>/mi,
        # Styling can position an invisible overlay over the page.
        'style_block' => /<style\b[^>]*>.*?<\/style>/mi
      }.freeze

      attr_reader :patterns

      def initialize(patterns: PATTERNS, name: 'markup', sides: [:output])
        super(name: name, sides: sides)
        @patterns = patterns
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
        cleaned = patterns.reduce(body) do |acc, (label, pattern)|
          acc.gsub(pattern) do
            found << label
            ''
          end
        end
        return pass if found.empty?

        modify(cleaned, categories: found.uniq,
                        reason: "removed #{found.uniq.join(', ')} from the answer")
      end
    end
  end
end
