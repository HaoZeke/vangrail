# frozen_string_literal: true

require 'uri'
require_relative '../rail'

module Vangrail
  module Rails
    # Strips outbound URLs an answer has no business emitting.
    #
    # This is the rail for the attack that does not need the reader to do
    # anything. A poisoned page tells the model to end its answer with a
    # markdown image whose URL carries the conversation in a query parameter;
    # the chat client renders markdown, so it fetches that URL by itself, and
    # the data is gone before anybody has read a word. The same trick with a
    # link needs one click, which a reader who trusts the assistant will give
    # it. Every shipped assistant that rendered markdown had this, and the fix
    # each of them landed on was the same: decide which hosts may be fetched,
    # and refuse the rest.
    #
    # So the rule here is an allowlist, and the default allowlist is empty,
    # because a documentation assistant answering from a handbook has exactly
    # one set of hosts worth linking to and the application knows what they are.
    #
    #   Rails::Exfiltration.new(allow_hosts: %w[docs.example.org example.org])
    #
    # Images are stricter than links: an image is fetched without consent, so a
    # host being allowlisted for links does not make it a place to auto-load
    # from unless `allow_images` names it too.
    #
    # It redacts rather than blocks. An answer with a bad link is a useful
    # answer with one bad span in it, and throwing away the help teaches readers
    # that the guardrail is the problem. The link text survives; the target does
    # not.
    class Exfiltration < Rail
      # Kept out of prose because a bare marker in the middle of a sentence
      # reads as an editing artefact, which is exactly what it is.
      PLACEHOLDER = '[link removed]'
      IMAGE_PLACEHOLDER = '[image removed]'

      # Markdown image, markdown link, bare HTML img/a, and anything with an
      # explicit scheme that is not http(s). Autolinks in angle brackets count:
      # some renderers fetch previews for them.
      IMAGE = /!\[([^\]]*)\]\(\s*<?([^)\s>]+)>?[^)]*\)/
      LINK = /(?<!!)\[([^\]]*)\]\(\s*<?([^)\s>]+)>?[^)]*\)/
      HTML_IMAGE = /<img\b[^>]*?\bsrc\s*=\s*["']?([^"'>\s]+)[^>]*>/i
      HTML_LINK = /<a\b[^>]*?\bhref\s*=\s*["']?([^"'>\s]+)[^>]*>(.*?)<\/a>/im
      AUTOLINK = /<((?:https?|data|file|ftp):\/\/[^>\s]+)>/i

      # A URL is suspicious on its own terms when it carries a payload: a long
      # query string, percent-encoded text, or a base64 run. An allowlisted host
      # with a hundred characters of query is still worth naming, because that
      # is what the exfiltration looks like when the attacker knows the
      # allowlist.
      PAYLOAD = /[?#].{40,}/
      ENCODED = /(?:%[0-9A-Fa-f]{2}){6,}|[A-Za-z0-9+\/]{40,}={0,2}/

      attr_reader :allow_hosts, :allow_images, :placeholder, :max_query

      def initialize(allow_hosts: [], allow_images: nil, placeholder: PLACEHOLDER,
                     max_query: 40, name: 'exfiltration', sides: [:output])
        super(name: name, sides: sides)
        @allow_hosts = normalise(allow_hosts)
        # nil means "the same hosts as links". An empty array means no images at
        # all, which is the safe reading of an application that never asked.
        @allow_images = allow_images.nil? ? @allow_hosts : normalise(allow_images)
        @placeholder = placeholder
        @max_query = max_query
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
        cleaned = strip_all(body, found)
        return pass if found.empty?

        modify(cleaned, categories: found.uniq,
                        reason: "removed #{found.uniq.join(', ')}")
      end

      # Whether this rail would leave the URL alone. Public because a caller
      # rendering its own links wants the same answer without a Result.
      def allowed?(url, image: false)
        host = host_of(url)
        return false if host.nil?

        list = image ? allow_images : allow_hosts
        return false unless list.any? { |h| host == h || host.end_with?(".#{h}") }

        !payload?(url)
      end

      private

      # The whole match is passed along rather than read back from
      # Regexp.last_match: a block shares its enclosing frame's match data, and a
      # method called from that block has its own, so a helper reading it would
      # see nothing.
      def strip_all(body, found)
        m = ->(n) { Regexp.last_match(n) }
        out = body.gsub(IMAGE) { redact_image(m[0], m[1], m[2], found) }
        out = out.gsub(LINK) { redact_link(m[0], m[1], m[2], found) }
        out = out.gsub(HTML_IMAGE) { redact_image(m[0], '', m[1], found) }
        out = out.gsub(HTML_LINK) { redact_link(m[0], m[2], m[1], found) }
        out.gsub(AUTOLINK) { redact_link(m[0], nil, m[1], found) }
      end

      def redact_image(whole, alt, url, found)
        return whole if allowed?(url, image: true)

        found << category(url, image: true)
        alt.to_s.empty? ? IMAGE_PLACEHOLDER : "#{alt} #{IMAGE_PLACEHOLDER}"
      end

      # The words stay, the destination goes. A reader still sees what the
      # answer meant to point at and can search for it.
      def redact_link(whole, label, url, found)
        return whole if allowed?(url)

        found << category(url)
        text = label.to_s.strip
        text.empty? ? placeholder : "#{text} #{placeholder}"
      end

      def category(url, image: false)
        return image ? 'foreign_image' : 'foreign_link' unless payload?(url)

        image ? 'image_payload' : 'link_payload'
      end

      # Long query strings and encoded runs are the payload itself. Checked
      # before the allowlist matters, so an allowlisted host cannot be used as
      # an open redirect for the same trick.
      def payload?(url)
        query = url.to_s[/[?#].*/].to_s
        return true if query.length > max_query
        return true if query.match?(PAYLOAD)

        query.match?(ENCODED)
      end

      # Anything without a parseable http(s) host is refused, which covers
      # data:, file:, javascript:, protocol-relative //evil, and the malformed
      # cases a renderer might still resolve.
      def host_of(url)
        uri = URI.parse(url.to_s.strip)
        return nil unless %w[http https].include?(uri.scheme)

        uri.host&.downcase
      rescue URI::InvalidURIError
        nil
      end

      def normalise(hosts)
        Array(hosts).map { |h| h.to_s.downcase.sub(/\Ahttps?:\/\//, '').split('/').first.to_s }
                    .reject(&:empty?).freeze
      end
    end
  end
end
