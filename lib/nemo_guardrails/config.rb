# frozen_string_literal: true

require 'fileutils'
require 'yaml'
require_relative 'policies'
require_relative 'willma'

module NemoGuardrails
  # Writes the configuration folder a NeMo Guardrails server loads: config.yml,
  # prompts.yml, and Colang flow files.
  #
  # This exists so the Ruby side owns one description of its rails. Without it a
  # policy lives twice, once in the Ruby guard-model path and once in a YAML tree
  # someone edits by hand, and the two drift.
  #
  #   NemoGuardrails::Config.surf_default(name: 'handbook').write!('config')
  #   # => config/handbook/{config.yml,prompts.yml,rails/output.co}
  #
  # Then: nemoguardrails server --config=config
  class Config
    attr_reader :name, :models, :rails, :prompts, :flows, :instructions, :sample_conversation

    def initialize(name:, models: [], rails: {}, prompts: [], flows: {}, instructions: nil,
                   sample_conversation: nil)
      @name = name
      @models = models
      @rails = rails
      @prompts = prompts
      @flows = flows
      @instructions = instructions
      @sample_conversation = sample_conversation
    end

    # A config wired to SURF AI Hub models: the main answer model plus a guard
    # model for the self-check rails. `engine: openai` with a custom base URL is
    # how an OpenAI-compatible gateway is reached, so the server needs
    # OPENAI_API_KEY and OPENAI_API_BASE in its own environment.
    def self.surf_default(name: 'handbook', main_model: 'openai/gpt-oss-120b',
                          guard_model: Willma::DEFAULT_GUARD_MODEL, base_url: Willma.base_url,
                          subject: 'a public documentation handbook')
      new(
        name: name,
        models: [
          {
            'type' => 'main',
            'engine' => 'openai',
            'model' => main_model,
            'parameters' => { 'base_url' => base_url }
          },
          {
            'type' => 'self_check_input',
            'engine' => 'openai',
            'model' => guard_model,
            'parameters' => { 'base_url' => base_url }
          },
          {
            'type' => 'self_check_output',
            'engine' => 'openai',
            'model' => guard_model,
            'parameters' => { 'base_url' => base_url }
          }
        ],
        rails: {
          'input' => { 'flows' => ['self check input'] },
          'output' => { 'flows' => ['self check output'] }
        },
        prompts: [
          { 'task' => 'self_check_input', 'content' => self_check_prompt(:input, subject) },
          { 'task' => 'self_check_output', 'content' => self_check_prompt(:output, subject) }
        ],
        instructions: [
          {
            'type' => 'general',
            'content' => "You answer questions about #{subject}. Every factual clause " \
                         'comes from a supplied passage. Where the passages do not cover ' \
                         'the question, say so.'
          }
        ]
      )
    end

    # NeMo's self-check tasks read a Yes/No answer, so the policy is rendered as
    # a question rather than the JSON contract the direct guard-model path uses.
    def self.self_check_prompt(rail, subject)
      policy = rail == :input ? Policies.input_policy(subject: subject) : Policies.output_policy(subject: subject)
      body = policy.sub(Policies::ANSWER_CONTRACT, '').rstrip
      slot = rail == :input ? '{{ user_input }}' : '{{ bot_response }}'
      label = rail == :input ? 'User message' : 'Bot message'
      <<~TXT
        #{body}

        #{label}: "#{slot}"

        Question: Should the message be blocked (Yes or No)?
        Answer:
      TXT
    end

    def to_h
      h = {}
      h['models'] = models unless models.empty?
      h['instructions'] = instructions if instructions
      h['rails'] = rails unless rails.empty?
      h['sample_conversation'] = sample_conversation if sample_conversation
      h
    end

    def config_yaml
      YAML.dump(to_h)
    end

    def prompts_yaml
      YAML.dump('prompts' => prompts)
    end

    # Writes <root>/<name>/. Returns the directory it wrote.
    def write!(root)
      dir = File.join(root, name)
      FileUtils.mkdir_p(dir)
      File.write(File.join(dir, 'config.yml'), config_yaml)
      File.write(File.join(dir, 'prompts.yml'), prompts_yaml) unless prompts.empty?
      unless flows.empty?
        FileUtils.mkdir_p(File.join(dir, 'rails'))
        flows.each { |file, colang| File.write(File.join(dir, 'rails', "#{file}.co"), colang.to_s) }
      end
      dir
    end
  end
end
