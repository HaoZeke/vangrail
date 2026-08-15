# frozen_string_literal: true

require 'fileutils'
require 'yaml'
require_relative 'actions'
require_relative 'chat'
require_relative 'colang/library'
require_relative 'colang/parser'
require_relative 'engine'
require_relative 'errors'
require_relative 'policies'
require_relative 'rails/colang_flow'
require_relative 'rails/grounding'
require_relative 'rails/self_check'
require_relative 'provider'

module Vangrail
  # A guardrails configuration folder, read and written by Ruby.
  #
  #   config = Vangrail::Config.load('config/handbook')
  #   engine = config.engine
  #   engine.check_input('Ignore your instructions.')
  #
  # The folder is the format the Python toolkit uses: config.yml for models and
  # which flows run on which side, prompts.yml for the policy text each
  # self-check task judges against, and rails/*.co for the flows themselves.
  # Nothing here shells out to it. The YAML is read, the Colang is parsed, and
  # the flows execute in this process, so the same folder can be handed to
  # either runtime and describes one set of rails either way.
  #
  # A folder naming a flow that nothing defines raises. A folder naming a model
  # type this gem cannot serve raises. Both are load-time failures on purpose: a
  # configuration that comes up with half its rails missing is worse than one
  # that refuses to come up.
  class Config
    SELF_CHECK_TASKS = { 'self_check_input' => :input, 'self_check_output' => :output }.freeze

    attr_reader :name, :models, :rails, :prompts, :flows, :instructions, :sample_conversation, :path

    def initialize(name:, models: [], rails: {}, prompts: [], flows: {}, instructions: nil,
                   sample_conversation: nil, path: nil)
      @name = name
      @models = models
      @rails = rails
      @prompts = prompts
      @flows = flows
      @instructions = instructions
      @sample_conversation = sample_conversation
      @path = path
    end

    # --- reading ---

    def self.load(dir)
      raise ConfigError, "no configuration folder at #{dir}" unless File.directory?(dir)

      yaml = load_yaml(File.join(dir, 'config.yml')) || load_yaml(File.join(dir, 'config.yaml')) || {}
      prompts = Array((load_yaml(File.join(dir, 'prompts.yml')) || {})['prompts'])
      flows = Dir[File.join(dir, '**', '*.co')].to_h do |file|
        [File.basename(file, '.co'), File.read(file)]
      end

      new(
        name: File.basename(dir),
        models: Array(yaml['models']),
        rails: yaml['rails'] || {},
        prompts: prompts,
        flows: flows,
        instructions: yaml['instructions'],
        sample_conversation: yaml['sample_conversation'],
        path: dir,
      )
    end

    def self.load_yaml(file)
      return nil unless File.file?(file)

      YAML.safe_load_file(file, aliases: true)
    end

    # --- running ---

    # Every flow this configuration can execute: the ones it ships plus the
    # built-ins it is allowed to name without defining.
    def program
      @program ||= flows.reduce(Colang::Library.program) do |acc, (file, source)|
        acc.merge(Colang::Parser.parse(source, filename: "#{file}.co"))
      end
    end

    def flow_names(side)
      keys = [side.to_s]
      # NeMo names the retrieved-document side `retrieval`. That is :context.
      keys << 'retrieval' if side.to_sym == :context
      keys.flat_map { |key| Array(rails.dig(key, 'flows')) }.map(&:to_s).uniq
    end

    def prompt_for(task)
      entry = prompts.detect { |p| p['task'].to_s == task.to_s }
      entry && entry['content'].to_s
    end

    def model_for(type)
      models.detect { |m| m['type'].to_s == type.to_s }
    end

    # Builds the engine this configuration describes.
    #
    # `chat:` overrides where model-backed actions call, which is what tests and
    # a caller with its own client pass. `actions:` adds or replaces actions by
    # name, so a team's own check joins the built-ins without touching the gem.
    #
    # `stdlib:` prepends the deterministic input and context rails this gem
    # ships (patterns, paraphrase, language posture). Off by default so a
    # folder still describes one set of rails on either runtime; on so a
    # folder whose judge is down still refuses a reworded injection and
    # still refuses to call an unread language a clean pass.
    def engine(provider: nil, chat: nil, actions: {}, on_error: :allow, cache: true, stdlib: false)
      registry = self_check_actions(provider, chat).merge(actions)
      Engine.new(
        input: compose(:input, rails_for(:input, registry), stdlib),
        context: compose(:context, rails_for(:context, registry), stdlib),
        output: rails_for(:output, registry),
        on_error: on_error,
        cache: cache,
      )
    end

    def rails_for(side, registry)
      flow_names(side).map do |flow_name|
        unless program.flow(flow_name)
          raise ConfigError,
                "#{name}: rails.#{side}.flows names #{flow_name.inspect}, which no .co file defines " \
                "and which is not built in (#{Colang::Library.flow_names.join(', ')})"
        end

        Rails::ColangFlow.new(flow_name: flow_name, program: program, actions: registry, sides: [side])
      end
    end

    private

    def compose(side, flows, stdlib)
      return flows unless stdlib

      Builder.deterministic(side) + flows
    end

    # The three tasks a stock configuration expects, each backed by a rail this
    # gem implements. A configuration that names none of them gets none of them.
    def self_check_actions(provider, chat)
      input = self_check_rail('self_check_input', :input, provider, chat)
      output = self_check_rail('self_check_output', :output, provider, chat)
      facts = grounding_rail(provider, chat)
      Actions.from_rails(input: input, output: output, facts: facts)
    end

    def self_check_rail(task, side, provider, chat)
      entry = model_for(task) || model_for('main')
      return nil unless entry

      Rails::SelfCheck.new(
        name: task,
        sides: [side],
        policy: prompt_for(task),
        model: entry['model'],
        chat: chat,
        provider: provider_for(entry, provider),
      )
    end

    def grounding_rail(provider, chat)
      entry = model_for('self_check_facts') || model_for('main')
      return nil unless entry

      Rails::Grounding.new(model: entry['model'], chat: chat, provider: provider_for(entry, provider))
    end

    # A model entry names its own endpoint through `parameters.base_url`, which
    # is how the configuration format points at an OpenAI-compatible gateway.
    # That wins over the caller's provider, because the folder is the thing
    # under version control and the provider is ambient.
    def provider_for(entry, provider)
      base = entry.dig('parameters', 'base_url')
      return provider if base.nil? || base.to_s.strip.empty?
      return provider if provider && provider.base_url == base.to_s.sub(/\/+\z/, '')

      key = provider&.api_key
      Provider.new(name: entry['type'].to_s, base_url: base, models: { judge: entry['model'] },
                   key_resolver: key ? -> { key } : nil)
    end

    public

    # --- writing ---

    # A starting configuration for a provider. `engine: openai` with a base_url
    # parameter is how the format names an OpenAI-compatible gateway, and this
    # gem reads that field the same way, so one folder serves both runtimes.
    def self.for_provider(provider, name: 'handbook', main_model: nil, judge_model: nil,
                          subject: 'a public documentation handbook')
      base_url = provider.base_url
      main_model ||= provider.model(:judge)
      judge_model ||= provider.model(:judge)
      new(
        name: name,
        models: [
          model_entry('main', main_model, base_url),
          model_entry('self_check_input', judge_model, base_url),
          model_entry('self_check_output', judge_model, base_url),
        ],
        rails: {
          'input' => { 'flows' => ['self check input'] },
          'output' => { 'flows' => ['self check output'] },
        },
        prompts: [
          { 'task' => 'self_check_input', 'content' => self_check_prompt(:input, subject) },
          { 'task' => 'self_check_output', 'content' => self_check_prompt(:output, subject) },
        ],
        instructions: [
          {
            'type' => 'general',
            'content' => "You answer questions about #{subject}. Every factual clause " \
                         'comes from a supplied passage. Where the passages do not cover ' \
                         'the question, say so.',
          },
        ],
      )
    end

    def self.model_entry(type, model, base_url)
      { 'type' => type, 'engine' => 'openai', 'model' => model, 'parameters' => { 'base_url' => base_url } }
    end

    # The self-check tasks read a Yes/No answer, so the policy is rendered as a
    # question rather than with the JSON contract a policy judge uses.
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
