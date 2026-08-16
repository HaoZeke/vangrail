# frozen_string_literal: true

module Vangrail
  # Reads the environment into an engine. A class rather than a method so each
  # decision is separable and testable on its own.
  class Builder
    DEFAULT_RAILS = %i[input context output].freeze
    ALL_RAILS = %i[input context output grounding secrets patterns links multiturn privacy
                   markup budget semantic perplexity bayes linear].freeze

    # Deterministic input patterns, kept small on purpose. Each is a phrase
    # whose presence is itself the violation; anything needing judgement belongs
    # in a policy rail, where a false positive is a model's opinion rather than
    # a hard rule.
    INJECTION_PATTERNS = {
      'instruction_override' => /\bignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)\s+instructions?\b/i,
      'prompt_disclosure' => /\b(?:reveal|print|repeat|show|output)\s+(?:me\s+)?(?:your|the|its)?\s*
                              (?:system\s+prompt|initial\s+instructions|developer\s+message)\b/xi,
      'role_reset' => /\byou\s+are\s+now\s+(?:a|an|in)\b.{0,40}\b(?:mode|persona|dan|jailbreak)\b/i,
    }.freeze

    attr_reader :env

    def initialize(env = ENV)
      @env = env
    end

    def engine
      return Engine.new(on_error: on_error, cache: cache?) if off?
      return config_engine if config_dir

      Engine.new(input: input_rails, context: context_rails, output: output_rails,
                 on_error: on_error, cache: cache?)
    end

    def session(prior:, **kwargs)
      Session.new(engine: engine, prior: prior, **kwargs)
    end

    # The offline stack that does not need a folder or an endpoint: patterns,
    # concepts, near-copies, the decoding pass, and the language posture.
    # `Config#engine(stdlib: true)` prepends the same list so a NeMo folder
    # does not certain-pass a question nothing here can read.
    def self.deterministic(side)
      side = side.to_sym
      return [] if side == :output

      core = [
        (Rails::InjectedInstructions.new if side == :context),
        (if side == :input
           Rails::Pattern.new(patterns: INJECTION_PATTERNS, name: 'injection_patterns',
                              sides: [side])
         end),
        Rails::Jailbreak.new(sides: [side]),
        Rails::Paraphrase.new(sides: [side]),
        Rails::Alignment.new(sides: [side]),
        Rails::Similarity.new(sides: [side]),
        Rails::ManyShot.new(sides: [side]),
      ].compact
      extras = [Rails::Obfuscation.new(rails: core, sides: [side])]
      extras << Rails::Hidden.new(rails: core) if side == :context
      extras << Rails::Language.new(sides: [side])
      core + extras
    end

    def enabled
      text = env['GUARDRAILS_RAILS'].to_s.strip
      return DEFAULT_RAILS if text.empty?
      return [] if off_value?(text) || text.casecmp('none').zero?
      return ALL_RAILS.dup if text.casecmp('all').zero?

      names = text.split(/[,\s]+/).map { |s| s.strip.downcase.to_sym }
      unknown = names - ALL_RAILS
      raise ArgumentError, "unknown rail name(s): #{unknown.join(', ')}" unless unknown.empty?

      names & ALL_RAILS
    end

    def on?(rail)
      enabled.include?(rail)
    end

    def off?
      off_value?(env['GUARDRAILS'])
    end

    def on_error
      env['GUARDRAILS_ON_ERROR'].to_s.strip.casecmp('block').zero? ? :block : :allow
    end

    def cache?
      !off_value?(env['GUARDRAILS_CACHE'])
    end

    def config_dir
      present(env['GUARDRAILS_CONFIG'])
    end

    def server_url
      present(env['GUARDRAILS_SERVER'])
    end

    # The endpoint the model-backed rails call, or nil when none is reachable.
    def provider
      return @provider if defined?(@provider)

      @provider = Provider.resolve(env)
    end

    private

    def config_engine
      Config.load(config_dir).engine(provider: provider, on_error: on_error, cache: cache?)
    end

    # The pattern rail runs whenever any input rail does. It costs microseconds
    # and it is the only part of the input side that still works when the
    # endpoint is down.
    def input_rails
      return [] unless on?(:input) || on?(:patterns)

      rails = self.class.deterministic(:input)
      # A question carrying the canary is too late to prevent and worth
      # knowing: the prompt is already out.
      rails << canary(:input) if canary_token
      # Opt-in: it rewrites the question before the model sees it, which is a
      # deployment's call rather than a default. Where the endpoint is a third
      # party it is close to obligatory, and where it is a local proxy it buys
      # little.
      rails << Rails::Bayes.new(sides: [:input]) if on?(:bayes)
      rails << Rails::Linear.new(sides: [:input]) if on?(:linear)
      rails << semantic(:input) if on?(:semantic)
      rails << perplexity(:input) if on?(:perplexity)
      rails << Rails::PersonalData.new if on?(:privacy)
      rails << Rails::Budget.new(sides: [:input]) if on?(:budget)
      # Off unless asked for: they read history, and a caller that threads none
      # would have every input check come back uncertain, which is true and
      # useless. Conversation is what makes them worth having.
      #
      # The deterministic one goes first so a refused question asked again
      # never reaches the judge: it is free, and the round trip is not.
      rails.concat(multiturn_rails) if on?(:multiturn)
      rails << judged(:input) if on?(:input)
      rails.compact
    end

    # Deterministic, offline, and free, so it is on by default. The document a
    # retrieval step just fetched is the side an attacker can usually reach
    # without touching the application, and nothing else in this engine reads it.
    #
    # The decoding pass matters more here than anywhere else: a page an
    # attacker edits is a page they can base64.
    def context_rails
      return [] unless on?(:context)

      # Two passes over the same definitions, for the two ways a page hides
      # one: encoded so the patterns cannot read it, or in markup a reader
      # never sees. Language sits outside the decoding pass and last among
      # the free rails: every rail above is a rule about English or Dutch
      # words, and a page in neither has been passed by all of them without
      # being read. Reporting that costs a token count and keeps `certain?`
      # honest.
      rails = self.class.deterministic(:context)
      rails << Rails::Bayes.new(sides: [:context]) if on?(:bayes)
      rails << Rails::Linear.new(sides: [:context]) if on?(:linear)
      rails << semantic(:context) if on?(:semantic)
      rails << perplexity(:context) if on?(:perplexity)
      rails << Rails::Budget.new(sides: [:context]) if on?(:budget)
      rails
    end

    def output_rails
      rails = []
      rails << Rails::Secrets.new if on?(:secrets) || on?(:output)
      rails << canary(:output) if canary_token
      # Naming the file is the opt-in, the same way the canary token is. Only
      # the application knows what its prompt says, and a rail that guessed
      # would be guarding a text nobody wrote.
      rails << prompt_leak if protected_prompt
      # Off by default: a desk whose client renders answers as plain text does
      # not need it, and stripping markup nobody would have executed is noise
      # in the result.
      rails << Rails::Markup.new if on?(:markup)
      rails << exfiltration if link_hosts || on?(:links)
      rails << judged(:output) if on?(:output)
      rails << grounding if on?(:grounding)
      rails.compact
    end

    # The hosts an answer may link to. Not defaulted to anything, because the
    # empty allowlist means "no links at all", which is right for an
    # application that said so and wrong to impose on one that never mentioned
    # links. Naming the variable is the opt-in.
    def link_hosts
      present(env['GUARDRAILS_LINK_HOSTS'])
    end

    # The pair, because they cover different halves. Escalation sees a retry
    # after a refusal and nothing before one; the judge reads a sequence that
    # has never been refused, which is what the published multi-turn methods
    # are built to produce.
    def multiturn_rails
      rails = [Rails::Escalation.new]
      rails << if provider&.available? && provider.model(:judge)
                 Rails::Trajectory.new(provider: provider, every: judge_every)
               else
                 missing('trajectory', :input)
               end
      rails
    end

    # One round trip per turn is the honest cost, and a desk may not want to
    # pay it every turn. A staged escalation takes several turns by
    # construction and cannot finish inside a gap of two.
    def judge_every
      value = env['GUARDRAILS_TRAJECTORY_EVERY'].to_i
      value.positive? ? value : 1
    end

    # The rail class follows what the endpoint can actually serve. A provider
    # hosting a classifier gets one; a provider serving only instruct models
    # gets a written policy in front of one, which is the same job done
    # differently rather than the same job skipped.
    def judged(side)
      return remote(side) if server_url
      return missing("#{side}_model", side) unless provider&.available?
      return guard_model(side) if provider.guard?
      return missing("#{side}_model", side) unless provider.model(:judge)

      Rails::SelfCheck.new(provider: provider, sides: [side], name: "policy_#{side}")
    end

    # Asked for and unbuildable. Kept in the list rather than dropped, so the
    # engine's pass stays uncertain instead of resting on the offline rails.
    #
    # `name` is what the rail would have been; `side` is where it would have
    # run. They are not the same thing, and conflating them is how a grounding
    # placeholder ends up claiming a side that does not exist.
    def missing(name, side)
      reason =
        if provider.nil?
          'no endpoint resolved: set GUARDRAILS_API_BASE, or start a local one'
        elsif provider.available? && provider.model(:judge).nil?
          'no judge model; set LLMLITE_MODEL or GUARDRAILS_JUDGE_MODEL'
        else
          "#{provider.name} is not available at #{provider.base_url}"
        end
      Rails::Missing.new(reason: reason, name: name.to_s, sides: [side])
    end

    def remote(side)
      Rails::Remote.new(base_url: server_url, config_id: present(env['GUARDRAILS_CONFIG_ID']),
                        api_key: present(env['GUARDRAILS_SERVER_API_KEY']), sides: [side])
    end

    def guard_model(side)
      Rails::GuardModel.new(provider: provider, reasoning: truthy?(env['GUARDRAILS_REASONING']),
                            sides: [side])
    end

    # The application generates the token, puts it in its prompt, and names it
    # here. Nothing can be checked without one, so its absence is the off
    # switch.
    def canary_token
      present(env['GUARDRAILS_CANARY'])
    end

    def canary(side)
      Rails::Canary.new(tokens: canary_token.split(/[,\s]+/), sides: [side])
    end

    # The text that must not come back out, read from a file because a system
    # prompt in an environment variable is a system prompt nobody can read.
    # An unreadable path raises rather than silently building no rail: a
    # guardrail that was asked for and quietly absent is the failure this gem
    # exists to prevent.
    def protected_prompt
      return @protected_prompt if defined?(@protected_prompt)

      path = present(env['GUARDRAILS_PROMPT_FILE'])
      @protected_prompt =
        if path.nil?
          nil
        else
          begin
            File.read(path)
          rescue SystemCallError => e
            raise ConfigError, "GUARDRAILS_PROMPT_FILE #{path.inspect} could not be read: #{e.message}"
          end
        end
    end

    # Asked for by name, because it costs a round trip per check and because
    # every document embedded on a third-party endpoint is a document sent
    # there. A provider serving no embedding model leaves the placeholder, so
    # the pass stays uncertain rather than resting on the offline rails.
    def semantic(side)
      return missing('semantic', side) unless provider&.available? && provider.embed?

      Rails::Semantic.new(embeddings: provider.embeddings, sides: [side],
                          threshold: semantic_threshold)
    end

    # Off unless asked for, and not only for the round trip: the threshold is a
    # property of the endpoint's model, and an uncalibrated detector switched on
    # by default is a detector that blocks somebody's shell transcript.
    def perplexity(side)
      return missing('perplexity', side) unless provider&.available? && provider.model(:judge)

      Rails::Perplexity.new(completion: provider.completion, sides: [side],
                            threshold: perplexity_threshold)
    end

    def perplexity_threshold
      value = env['GUARDRAILS_PERPLEXITY_THRESHOLD'].to_f
      value.positive? ? value : Rails::Perplexity::THRESHOLD
    end

    def semantic_threshold
      value = env['GUARDRAILS_SEMANTIC_THRESHOLD'].to_f
      value.positive? ? value : Rails::Semantic::THRESHOLD
    end

    def prompt_leak
      Rails::PromptLeak.new(protected_text: protected_prompt)
    end

    def exfiltration
      hosts = link_hosts.to_s.split(/[,\s]+/).reject(&:empty?)
      images = present(env['GUARDRAILS_IMAGE_HOSTS'])
      Rails::Exfiltration.new(allow_hosts: hosts,
                              allow_images: images&.split(/[,\s]+/)&.reject(&:empty?))
    end

    def grounding
      return missing('grounding', :output) unless provider&.available? && provider.model(:judge)

      Rails::Grounding.new(provider: provider)
    end

    def off_value?(value)
      %w[0 off false no].include?(value.to_s.strip.downcase)
    end

    def truthy?(value)
      %w[1 on true yes].include?(value.to_s.strip.downcase)
    end

    def present(value)
      s = value.to_s.strip
      s.empty? ? nil : s
    end
  end
end
