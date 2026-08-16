# frozen_string_literal: true

require_relative '../rail'

module Vangrail
  module Rails
    # Fingerprints for the jailbreak shapes that circulate.
    #
    # The in-the-wild corpora show the same handful of wrappers recurring for
    # years: a persona with no restrictions, a claim that safety was disabled
    # for testing, a demand for two answers of which one is unfiltered, a
    # grandmother who used to read out license keys. They survive because they
    # work often enough, and they are worth matching directly for the same
    # reason a spam filter matches a known campaign: the cost of a hit is
    # microseconds and the shapes have no honest use.
    #
    # This is a floor, not a defence. Rephrasing beats a pattern, and anything
    # novel walks straight past it. What it buys is that the copied-and-pasted
    # majority never reaches a model, and that it keeps working when the model
    # rail is unreachable.
    #
    # Kept apart from Rails::Pattern, which is generic, because these want their
    # own false-positive budget: a documentation desk discusses roles, modes,
    # and restrictions all day, so every pattern here is checked against
    # ordinary handbook prose in the suite.
    class Jailbreak < Rail
      PATTERNS = {
        # A named persona whose defining trait is having no rules.
        'unrestricted_persona' => /
          \b(?:you\s+are|act\s+as|pretend\s+to\s+be|simulate|roleplay\s+as)\b[^.\n]{0,60}?
          \b(?:dan|do\s+anything\s+now|developer\s+mode|jailbroken|unfiltered|
             unrestricted|without\s+(?:any\s+)?(?:restrictions?|filters?|guidelines?|rules?))\b
        /xi,
        # A claim that the rules are off, usually dressed as authority.
        'restrictions_lifted' => /
          \b(?:safety|content|ethical|moral)\s+(?:filters?|guidelines?|restrictions?|policies|protocols?)\b
          [^.\n]{0,40}\b(?:disabled|removed|lifted|off|bypassed|no\s+longer\s+apply)\b
          |
          # Addressed to the assistant, not describing a machine. "The
          # scheduler runs in developer mode" is a sysadmin sentence; "enter
          # developer mode" is an instruction to the model.
          \b(?:enter|activate|enable|switch\s+to|you\s+are\s+(?:now\s+)?in)\s+
          (?:developer|debug|god|sudo|admin|dan)\s+mode\b
          |
          # The bare declarative form, at the start of a clause and with the
          # words adjacent. "The admin mode on the appliance is enabled"
          # separates them and keeps its subject; "Developer mode enabled."
          # does neither, because it is an instruction wearing a status
          # report. admin is left out here: a storage appliance really does
          # have one.
          (?:\A|[.!?]\s+)(?:developer|debug|god|sudo|dan)\s+mode\s+(?:enabled|activated)\b
        /xi,
        # Two answers, one of them the real one.
        'dual_answer' => /
          \b(?:respond|answer|reply|output)\b[^.\n]{0,40}\b(?:two|both|2)\b[^.\n]{0,30}
          \b(?:ways?|versions?|responses?|answers?)\b
          |
          \[?\s*(?:classic|jailbreak|normal|developer\s+mode)\s+(?:output|response)\s*\]?\s*:
        /xi,
        # The sympathy wrapper: a relative, a bedtime story, a dying wish.
        'sentimental_wrapper' => /
          \b(?:my\s+)?(?:grandmother|grandma|late\s+\w+)\b[^.\n]{0,60}
          \b(?:used\s+to|would)\b[^.\n]{0,40}\b(?:read|tell|recite|whisper)\b
        /xi,
        # Fiction as a licence: the harmful part is what the character says.
        'fiction_licence' => /
          \b(?:write|compose|imagine)\b[^.\n]{0,40}\b(?:story|script|screenplay|novel|play)\b
          [^.\n]{0,60}\bwhere\b[^.\n]{0,60}\b(?:explains?|describes?|details?|teaches?)\b
          [^.\n]{0,40}\b(?:how\s+to\s+(?:make|build|synthesi[sz]e|hack|exploit))\b
        /xi,
        # An appeal to a higher authority that does not exist in the channel.
        #
        # The roles are named rather than the vendors. A wrapper saying "this is
        # <lab name>" is one string edit away from saying another, so the second
        # branch matches the grant clause instead: an arbitrary claimed identity
        # followed by permission being conferred. That clause is what makes the
        # sentence an attack, and it is not something a handbook says.
        'forged_authority' => /
          \b(?:as\s+(?:your|the)\s+(?:developer|creator|administrator|owner|vendor|provider)|
             this\s+is\s+(?:your\s+)?
             (?:developer|creator|admin|vendor|provider|maker|
                (?:the\s+)?(?:company|lab|team)\s+that\s+(?:made|built|trained)\s+you))\b
          [^.\n]{0,40}\b(?:i\s+(?:am\s+)?(?:instruct|order|command|authori[sz]e)|
             you\s+(?:must|are\s+(?:now\s+)?(?:required|permitted|allowed)))\b
          |
          \bthis\s+is\s+(?:the\s+)?[a-z][\w.-]*(?:\s+(?:ai|inc|labs?))?\b[^.\n]{0,30}
          \byou\s+are\s+now\s+(?:permitted|allowed|required|authori[sz]ed)\b
        /xi,
      }.freeze

      attr_reader :patterns

      def initialize(patterns: PATTERNS, name: 'jailbreak', sides: %i[input context])
        super(name: name, sides: sides)
        @patterns = patterns
      end

      def cache_key(text, _context)
        text
      end

      def decide(text, _context)
        hits = patterns.select { |_label, pattern| pattern.match?(text.to_s) }.keys
        return pass if hits.empty?

        block(categories: hits, reason: "known jailbreak shape: #{hits.join(', ')}")
      end
    end
  end
end
