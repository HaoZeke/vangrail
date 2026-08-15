# frozen_string_literal: true

require_relative 'errors'

module Vangrail
  # Named callables a Conversation may invoke, and only after Admission
  # says so. The handler never sees a request that was not granted.
  #
  #   tools = Tools.new
  #   tools.register(:cite) { |args, convo| ... }
  #   convo = Conversation.new(engine, allow: { cite: %i[data] }, tools: tools)
  #   convo.ask('Cite the partition table.')
  #   convo.invoke(:cite, arguments: page)
  class Tools
    def initialize(handlers = {})
      @handlers = {}
      handlers.each { |name, fn| register(name, fn) }
    end

    def register(name, callable = nil, &block)
      fn = callable || block
      raise ArgumentError, "tool #{name} needs a callable" unless fn.respond_to?(:call)

      @handlers[name.to_sym] = fn
      self
    end

    def key?(name)
      @handlers.key?(name.to_sym)
    end

    def names
      @handlers.keys
    end

    def call(name, arguments, conversation)
      raise ArgumentError, "unknown tool #{name}" unless key?(name)

      @handlers[name.to_sym].call(arguments, conversation)
    end

    def dup
      self.class.new(@handlers.dup)
    end

    def to_h
      @handlers.dup
    end
  end
end
