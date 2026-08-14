# frozen_string_literal: true

require_relative 'errors'

module NemoGuardrails
  # Ruby callables a Colang flow can execute.
  #
  # An action receives (arguments_hash, context) and returns whatever the flow
  # will branch on: usually true or false, sometimes a rewritten string. Nothing
  # about an action is special, which is the point. A team's own check is a
  # lambda, registered by name, and a flow calls it exactly like a built-in.
  #
  #   actions = NemoGuardrails::Actions.new
  #   actions.register('check_ticket_id') { |_args, ctx| ctx[:user_input].match?(/EINF-\d+/) }
  class Actions
    def initialize(handlers = {})
      @handlers = {}
      handlers.each { |name, fn| register(name, &fn) }
    end

    def register(name, callable = nil, &block)
      fn = callable || block
      raise ArgumentError, "action #{name} needs a callable" unless fn.respond_to?(:call)

      @handlers[name.to_s] = fn
      self
    end

    def [](name)
      @handlers[name.to_s]
    end

    def key?(name)
      @handlers.key?(name.to_s)
    end

    def names
      @handlers.keys.sort
    end

    def merge(other)
      self.class.new(to_h.merge(other.respond_to?(:to_h) ? other.to_h : other))
    end

    def to_h
      @handlers.dup
    end

    # Wraps rails as the actions the toolkit's own flows call by name, so a
    # config folder written for the Python runtime finds what it expects.
    # `self_check_input` returns true when the text is allowed, which is the
    # polarity those flows branch on.
    def self.from_rails(input: nil, output: nil, facts: nil)
      actions = new
      actions.register('self_check_input') { |_args, ctx| input && input.call(ctx[:text], ctx).allowed? }
      actions.register('self_check_output') { |_args, ctx| output && output.call(ctx[:text], ctx).allowed? }
      actions.register('self_check_facts') { |_args, ctx| facts && facts.call(ctx[:text], ctx).allowed? }
      actions
    end
  end
end
