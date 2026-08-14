# frozen_string_literal: true

require 'json'

module Vangrail
  # Readers for what guard and judge models actually answer.
  #
  # Each returns a hash: {decided:, violated:, categories:, reason:}. `decided`
  # false means the text was not in a form this code understands, which a rail
  # turns into an uncertain result rather than a pass. Guessing at an unreadable
  # answer is how a guardrail comes to report checks it never made.
  module Parsers
    module_function

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

    # "safe" or "unsafe\nS1,S10".
    def llama_guard(text)
      lines = clean_lines(text)
      head = lines.first.to_s.downcase
      return undecided(text) unless head.start_with?('safe', 'unsafe')
      return clean if head.start_with?('safe')

      codes = codes_in(lines[1..]&.join(','), /S\d{1,2}/i)
      { decided: true, violated: true, categories: codes,
        reason: describe(codes, LLAMA_GUARD_CATEGORIES, 'unsafe') }
    end

    # "safe\nnon_adversarial" or "unsafe-O14,O12\nadversarial". Either line can
    # condemn the turn: a jailbreak attempt with no hazard category is still one.
    # With reasoning on the same two verdicts arrive as labelled fields after
    # their assessments, so that form is tried first.
    def apriel_guard(text)
      reasoned = apriel_guard_reasoned(text)
      return reasoned if reasoned

      lines = clean_lines(text)
      safety = lines.find { |l| l.match?(/\A(safe|unsafe)/i) }
      adversarial = lines.find { |l| l.match?(/\A(non_adversarial|adversarial)/i) }
      return undecided(text) if safety.nil? && adversarial.nil?

      unsafe = safety.to_s.match?(/\Aunsafe/i)
      attack = adversarial.to_s.match?(/\Aadversarial/i)
      return clean unless unsafe || attack

      codes = codes_in(safety, /O\d{1,2}/i)
      codes += ['adversarial'] if attack
      reason = unsafe ? describe(codes - ['adversarial'], {}, 'unsafe') : 'adversarial input'
      { decided: true, violated: true, categories: codes, reason: reason }
    end

    # Reasoning mode:
    #
    #   safety_risks_assessment_reasoning: ## Step 1 ...
    #   safety_risks_class: unsafe,
    #   safety_risks_categories: ['O15'],
    #   adversarial_attacks_assessment_reasoning: ## Step 1 ...
    #   adversarial_attacks_class: adversarial
    #
    # nil when the text is not in this form, so the caller can try the short one.
    def apriel_guard_reasoned(text)
      body = text.to_s
      return nil unless body.include?('safety_risks_class')

      fields = {}
      body.each_line do |line|
        m = line.chomp.match(
          /\A(safety_risks_class|safety_risks_categories|adversarial_attacks_class)\s*:\s*(.*)\z/
        )
        fields[m[1]] = m[2].strip.sub(/,\z/, '') if m
      end
      unsafe = fields['safety_risks_class'].to_s.match?(/unsafe/i)
      attack = fields['adversarial_attacks_class'].to_s.match?(/\Aadversarial/i)
      return clean unless unsafe || attack

      codes = codes_in(fields['safety_risks_categories'], /O\d{1,2}/i)
      codes += ['adversarial'] if attack
      block = unsafe ? 'safety_risks' : 'adversarial_attacks'
      { decided: true, violated: true, categories: codes, reason: rationale(body, block) }
    end

    # A JSON verdict first, then a bare 0/1, then Yes/No. All three appear
    # depending on which answer contract a policy prompt asked for.
    def policy(text)
      body = text.to_s
      from_json = policy_json(body)
      return from_json if from_json

      stripped = body.strip
      return (stripped.start_with?('0') ? clean : violation) if stripped.match?(/\A[01]\b/)

      case stripped
      when /\Ayes\b/i then violation(reason: 'policy judge said yes')
      when /\Ano\b/i then clean
      else undecided(body)
      end
    end

    def policy_json(body)
      obj = first_json_object(body)
      return nil unless obj

      value = obj['violation']
      return nil unless [0, 1, true, false, '0', '1'].include?(value)
      return clean unless [1, true, '1'].include?(value)

      cats = [obj['policy_category'], *Array(obj['rule_ids'])].compact.map(&:to_s).reject(&:empty?)
      violation(categories: cats, reason: (obj['rationale'] || cats.join(',')).to_s[0, 240])
    end

    # First balanced {...}, so a fenced or prefaced verdict still reads.
    def first_json_object(text)
      start = text.index('{')
      return nil unless start

      depth = 0
      text[start..].each_char.with_index do |ch, i|
        depth += 1 if ch == '{'
        next unless ch == '}'

        depth -= 1
        return JSON.parse(text[start, i + 1]) if depth.zero?
      end
      nil
    rescue JSON::ParserError
      nil
    end

    # Last step of an assessment block, where the model states its conclusion
    # rather than restating the input.
    def rationale(body, block)
      section = body[/#{block}_assessment_reasoning:(.*?)(?=^[a-z_]+:)/m, 1]
      return nil unless section

      steps = section.split(/^##\s*Step\s*\d+\s*$/m).map(&:strip).reject(&:empty?)
      (steps.last || section).gsub(/\s+/, ' ').strip[0, 240]
    end

    def clean
      { decided: true, violated: false, categories: [], reason: nil }
    end

    def violation(categories: [], reason: nil)
      { decided: true, violated: true, categories: categories, reason: reason }
    end

    def undecided(text)
      { decided: false, violated: false, categories: [], reason: text.to_s.strip[0, 120] }
    end

    def clean_lines(text)
      text.to_s.strip.lines.map(&:strip).reject(&:empty?)
    end

    def codes_in(text, pattern)
      text.to_s.scan(pattern).map(&:upcase).uniq
    end

    def describe(codes, names, fallback)
      return fallback if codes.empty?

      codes.map { |c| names[c] ? "#{c} #{names[c]}" : c }.join(', ')
    end
  end
end
