# frozen_string_literal: true

require_relative 'errors'
require_relative 'origin'

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
    Entry = Struct.new(:handler, :readonly, :output, keyword_init: true)

    def initialize(handlers = {})
      @handlers = {}
      handlers.each { |name, fn| register(name, fn) }
    end

    def register(name, callable = nil, readonly: false, output: Origin.tool, &block)
      fn = callable || block
      raise ArgumentError, "tool #{name} needs a callable" unless fn.respond_to?(:call)

      output_label = output.is_a?(Label) ? output : Label.new(provenance: output)
      @handlers[name.to_sym] = Entry.new(handler: fn, readonly: readonly, output: output_label)
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

    def dispatch(name, arguments, conversation, authorization:)
      monitor = conversation&.monitor
      unless authorization&.call&.tool == name.to_sym && monitor&.claim(authorization)
        raise PrivilegeError, 'tool dispatch requires a live authorization'
      end

      value = fire(name, arguments, conversation)
      label_output(name, value, authorization.call)
    end

    def dup
      copy = self.class.new
      @handlers.each do |name, entry|
        copy.register(name, entry.handler, readonly: entry.readonly, output: entry.output)
      end
      copy
    end

    def to_h
      @handlers.transform_values(&:handler)
    end

    private

    def fire(name, arguments, conversation)
      raise ArgumentError, "unknown tool #{name}" unless key?(name)

      @handlers[name.to_sym].handler.call(arguments, conversation)
    end

    def label_output(name, value, call)
      entry = @handlers.fetch(name.to_sym)
      output = value.is_a?(Cell) ? value : Cell.new(value, label: entry.output)
      influenced = call.fields.values.reduce(output) do |cell, argument|
        cell.mix(argument, value: cell.raw)
      end
      influenced.mix(call.request, value: influenced.raw)
    end
  end
end
