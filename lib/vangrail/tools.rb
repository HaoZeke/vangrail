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
    Entry = Struct.new(:handler, :readonly, keyword_init: true)

    def initialize(handlers = {})
      @handlers = {}
      handlers.each { |name, fn| register(name, fn) }
    end

    def register(name, callable = nil, readonly: false, &block)
      fn = callable || block
      raise ArgumentError, "tool #{name} needs a callable" unless fn.respond_to?(:call)

      @handlers[name.to_sym] = Entry.new(handler: fn, readonly: readonly)
      self
    end

    def key?(name)
      @handlers.key?(name.to_sym)
    end

    def readonly?(name)
      !!@handlers[name.to_sym]&.readonly
    end

    def names
      @handlers.keys
    end

    def call(_name, _arguments, _conversation)
      raise PrivilegeError, 'use Conversation#invoke'
    end

    def fire(name, arguments, conversation)
      raise ArgumentError, "unknown tool #{name}" unless key?(name)

      @handlers[name.to_sym].handler.call(arguments, conversation)
    end

    def dup
      copy = self.class.new
      @handlers.each { |name, entry| copy.register(name, entry.handler, readonly: entry.readonly) }
      copy
    end

    def to_h
      @handlers.transform_values(&:handler)
    end
  end
end
