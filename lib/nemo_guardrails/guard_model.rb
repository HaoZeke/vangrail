# frozen_string_literal: true

require 'json'
require_relative 'errors'
require_relative 'http'
require_relative 'policies'
require_relative 'verdict'
require_relative 'willma'

module NemoGuardrails
  # A rail that calls a guard model directly over an OpenAI-compatible endpoint,
  # with no NeMo Guardrails server in the path.
  #
  # The server is the richer option: Colang dialog flows, config bundles, its own
  # observability. It is also a Python service to deploy and keep running. A Ruby
  # application that only needs input and output rails can spend one HTTP call
  # per rail instead, against the same guard models the server would call.
  #
  # Three response shapes are read, picked by preset:
  #
  #   :llama_guard   "safe" | "unsafe\nS1,S10"          (Llama Guard 3)
  #   :apriel_guard  "safe\nnon_adversarial" |
  #                  "unsafe-O14,O12\nadversarial"      (AprielGuard)
  #   :policy        {"violation": 0|1, ...} | 0/1 | Yes/No
  #
  # The first two get the text as chat messages and let the model's own chat
  # template do the framing. The third puts a policy in the system message.
  class GuardModel
    COMPLETIONS_PATH = '/chat/completions'

    # Llama Guard 3 hazard codes, the MLCommons taxonomy the model card lists.
    LLAMA_GUARD_CATEGORIES = {
      'S1' => 'Violent Crimes',
      'S2' => 'Non-Violent Crimes',
      'S3' => 'Sex-Related Crimes',
      'S4' => 'Child Sexual Exploitation',
      'S5' => 'Defamation',
      'S6' => 'Specialized Advice',
      'S7' => 'Privacy',
      'S8' => 'Intellectual Property',
      'S9' => 'Indiscriminate Weapons',
      'S10' => 'Hate',
      'S11' => 'Suicide & Self-Harm',
      'S12' => 'Sexual Content',
      'S13' => 'Elections',
      'S14' => 'Code Interpreter Abuse'
    }.freeze

    PRESETS = %i[llama_guard apriel_guard policy].freeze

    attr_reader :model, :preset, :http, :max_tokens, :temperature

    def initialize(model: nil, preset: nil, base_url: nil, api_key: nil, http: nil,
                   max_tokens: 128, temperature: 0,
                   open_timeout: HTTP::DEFAULT_OPEN_TIMEOUT, read_timeout: 20)
      @model = model || Willma.guard_model
      @preset = (preset || Willma.preset_for(@model)).to_sym
      raise ArgumentError, "preset must be one of #{PRESETS.join(', ')}" unless PRESETS.include?(@preset)

      @max_tokens = max_tokens
      @temperature = temperature
      @http = http || HTTP.new(
        base_url: base_url || Willma.base_url,
        api_key: api_key || Willma.token,
        open_timeout: open_timeout,
        read_timeout: read_timeout
      )
    end

    # Classify a user turn.
    def check_input(text, policy: nil)
      case preset
      when :policy
        judge(policy || Policies.input_policy, text.to_s, rail: :input)
      else
        classify([{ 'role' => 'user', 'content' => text.to_s }], rail: :input)
      end
    end

    # Classify an assistant turn. Guard models read the conversation, so the
    # user turn is part of the input when it is known.
    def check_output(text, user_input: nil, policy: nil)
      case preset
      when :policy
        judge(policy || Policies.output_policy, text.to_s, rail: :output)
      else
        messages = []
        messages << { 'role' => 'user', 'content' => user_input.to_s } unless user_input.to_s.strip.empty?
        messages << { 'role' => 'assistant', 'content' => text.to_s }
        classify(messages, rail: :output)
      end
    end

    # Does the answer say only what the passages support. Always a policy call:
    # safety classifiers score hazards, not attribution.
    def check_grounding(answer, passages:, model: nil)
      judge(
        Policies.grounding_policy,
        Policies.grounding_prompt(answer, passages),
        rail: :grounding,
        model: model,
        max_tokens: 256
      )
    end

    private

    def classify(messages, rail:)
      body, ms = complete(messages: messages)
      text = content_of(body)
      parsed = preset == :apriel_guard ? parse_apriel(text) : parse_llama_guard(text)
      build_verdict(parsed, rail: rail, latency_ms: ms, raw: body)
    end

    def judge(policy, content, rail:, model: nil, max_tokens: nil)
      body, ms = complete(
        messages: [
          { 'role' => 'system', 'content' => policy },
          { 'role' => 'user', 'content' => content }
        ],
        model: model,
        max_tokens: max_tokens
      )
      parsed = parse_policy(content_of(body))
      build_verdict(parsed, rail: rail, latency_ms: ms, raw: body)
    end

    def build_verdict(parsed, rail:, latency_ms:, raw:)
      if parsed[:decided]
        return Verdict.new(
          allowed: parsed[:allowed], rail: rail, reason: parsed[:reason],
          categories: parsed[:categories], model: model, latency_ms: latency_ms, raw: raw
        )
      end

      # An answer this client cannot read is not a clean bill of health. Allow
      # the turn, but mark the verdict uncertain so a caller that reports its
      # safety posture does not claim a check that did not resolve.
      Verdict.new(
        allowed: true, certain: false, rail: rail, model: model, latency_ms: latency_ms, raw: raw,
        reason: "unparsed guard response: #{parsed[:reason]}"
      )
    end

    def complete(messages:, model: nil, max_tokens: nil)
      payload = {
        'model' => model || @model,
        'messages' => messages,
        'temperature' => temperature,
        'max_tokens' => max_tokens || @max_tokens,
        'stream' => false
      }
      t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      body = http.post_json(COMPLETIONS_PATH, payload)
      [body, ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0) * 1000).round]
    end

    def content_of(body)
      choices = body.is_a?(Hash) ? body['choices'] : nil
      msg = choices.is_a?(Array) ? choices.dig(0, 'message') : nil
      text = msg.is_a?(Hash) ? msg['content'].to_s : ''
      # Reasoning models spend the budget on `reasoning` and can return a null
      # content. Fall back to the reasoning text rather than reading nothing.
      text = msg['reasoning'].to_s if text.strip.empty? && msg.is_a?(Hash)
      text
    end

    # "safe" or "unsafe\nS1,S10".
    def parse_llama_guard(text)
      lines = text.to_s.strip.lines.map(&:strip).reject(&:empty?)
      head = lines.first.to_s.downcase
      return undecided(text) unless head.start_with?('safe', 'unsafe')
      return { decided: true, allowed: true, categories: [], reason: nil } if head.start_with?('safe')

      codes = extract_codes(lines[1..]&.join(','), /S\d{1,2}/i)
      {
        decided: true, allowed: false, categories: codes,
        reason: describe(codes, LLAMA_GUARD_CATEGORIES, 'unsafe')
      }
    end

    # "safe\nnon_adversarial" or "unsafe-O14,O12\nadversarial". Either line can
    # condemn the turn: a jailbreak attempt with no hazard category is still one.
    def parse_apriel(text)
      lines = text.to_s.strip.lines.map(&:strip).reject(&:empty?)
      safety = lines.find { |l| l.match?(/\A(safe|unsafe)/i) }
      adversarial = lines.find { |l| l.match?(/\A(non_adversarial|adversarial)/i) }
      return undecided(text) if safety.nil? && adversarial.nil?

      unsafe = safety.to_s.match?(/\Aunsafe/i)
      attack = adversarial.to_s.match?(/\Aadversarial/i)
      codes = extract_codes(safety, /O\d{1,2}/i)
      codes += ['adversarial'] if attack
      return { decided: true, allowed: true, categories: [], reason: nil } unless unsafe || attack

      reason = unsafe ? describe(codes - ['adversarial'], {}, 'unsafe') : 'adversarial input'
      { decided: true, allowed: false, categories: codes, reason: reason }
    end

    # JSON verdict first, then a bare 0/1, then Yes/No.
    def parse_policy(text)
      body = text.to_s
      if (obj = first_json_object(body))
        v = obj['violation']
        decided = [0, 1, true, false, '0', '1'].include?(v)
        if decided
          violated = [1, true, '1'].include?(v)
          cats = [obj['policy_category'], *Array(obj['rule_ids'])].compact.map(&:to_s).reject(&:empty?)
          return {
            decided: true, allowed: !violated, categories: violated ? cats : [],
            reason: violated ? (obj['rationale'] || cats.join(',')).to_s[0, 200] : nil
          }
        end
      end

      stripped = body.strip
      return { decided: true, allowed: stripped.start_with?('0'), categories: [], reason: nil } if stripped.match?(/\A[01]\b/)

      case stripped
      when /\Ayes\b/i then { decided: true, allowed: false, categories: [], reason: 'policy judge said yes' }
      when /\Ano\b/i then { decided: true, allowed: true, categories: [], reason: nil }
      else undecided(body)
      end
    end

    def first_json_object(text)
      start = text.index('{')
      return nil unless start

      depth = 0
      text[start..].each_char.with_index do |ch, i|
        depth += 1 if ch == '{'
        if ch == '}'
          depth -= 1
          return JSON.parse(text[start, i + 1]) if depth.zero?
        end
      end
      nil
    rescue JSON::ParserError
      nil
    end

    def extract_codes(text, pattern)
      text.to_s.scan(pattern).map(&:upcase).uniq
    end

    def describe(codes, names, fallback)
      return fallback if codes.empty?

      codes.map { |c| names[c] ? "#{c} #{names[c]}" : c }.join(', ')
    end

    def undecided(text)
      { decided: false, reason: text.to_s.strip[0, 120] }
    end
  end
end
