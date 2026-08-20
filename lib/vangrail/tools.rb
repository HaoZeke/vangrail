# frozen_string_literal: true

require 'securerandom'
require_relative 'errors'
require_relative 'origin'

module Vangrail
  # Opaque prepared state for one transactional Call.
  class PreparedTransaction
    attr_reader :id, :call_id, :fingerprint, :tool, :payload, :state

    def initialize(call, payload)
      @id = SecureRandom.uuid.freeze
      @call_id = call.id
      @fingerprint = call.fingerprint.freeze
      @tool = call.tool
      @payload = payload
      @state = :prepared
    end

    def prepared?
      state == :prepared
    end

    def commit!
      @state = :committed
    end

    def rollback!
      @state = :rolled_back
    end
  end

  # Named callables a Conversation may invoke, and only after Admission
  # says so. The handler never sees a request that was not granted.
  #
  #   tools = Tools.new
  #   tools.register(:cite) { |args, convo| ... }
  #   convo = Conversation.new(engine, allow: { cite: %i[data] }, tools: tools)
  #   convo.ask('Cite the partition table.')
  #   convo.invoke(:cite, arguments: page)
  class Tools
    Transaction = Struct.new(:prepare, :commit, :rollback, keyword_init: true)
    Entry = Struct.new(:handler, :readonly, :output, :transaction, keyword_init: true)

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

    def register_transactional(name, prepare:, commit:, rollback:, output: Origin.tool)
      callbacks = { prepare: prepare, commit: commit, rollback: rollback }
      callbacks.each do |phase, callback|
        raise ArgumentError, "transaction #{phase} needs a callable" unless callback.respond_to?(:call)
      end

      output_label = output.is_a?(Label) ? output : Label.new(provenance: output)
      contract = Transaction.new(**callbacks).freeze
      @handlers[name.to_sym] = Entry.new(
        handler: nil,
        readonly: false,
        output: output_label,
        transaction: contract,
      )
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

    def transactional?(name)
      !@handlers[name.to_sym]&.transaction.nil?
    end

    def call(_name, _arguments, _conversation)
      raise PrivilegeError, 'use Conversation#invoke'
    end

    def prepare_transaction(name, arguments, conversation, call:)
      entry = @handlers[name.to_sym]
      return nil unless call.transaction? && entry&.transaction

      payload = entry.transaction.prepare.call(arguments, conversation)
      PreparedTransaction.new(call, payload).tap do |prepared|
        conversation.monitor.prepare_transaction(call, prepared)
      end
    rescue StandardError
      entry.transaction.rollback.call(payload, conversation) if defined?(payload) && entry&.transaction
      raise
    end

    def rollback_transaction(prepared, conversation)
      return unless prepared&.prepared?

      entry = @handlers.fetch(prepared.tool)
      entry.transaction.rollback.call(prepared.payload, conversation)
      prepared.rollback!
      conversation.monitor.finish_transaction(prepared, committed: false)
    end

    def dispatch(name, arguments, conversation, authorization:, transaction: nil)
      monitor = conversation&.monitor
      unless authorization&.call&.tool == name.to_sym && monitor&.claim(authorization)
        raise PrivilegeError, 'tool dispatch requires a live authorization'
      end

      value = if transaction
                commit_transaction(name, transaction, conversation)
              else
                fire(name, arguments, conversation)
              end
      label_output(name, value, authorization.call)
    rescue StandardError
      rollback_transaction(transaction, conversation) if transaction&.prepared?
      raise
    end

    def dup
      copy = self.class.new
      @handlers.each do |name, entry|
        if entry.transaction
          copy.register_transactional(name, output: entry.output, **entry.transaction.to_h)
        else
          copy.register(name, entry.handler, readonly: entry.readonly, output: entry.output)
        end
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

    def commit_transaction(name, prepared, conversation)
      entry = @handlers.fetch(name.to_sym)
      unless entry.transaction && prepared.prepared? && prepared.tool == name.to_sym
        raise PrivilegeError, 'transaction is not prepared for this tool'
      end

      entry.transaction.commit.call(prepared.payload, conversation).tap do
        prepared.commit!
        conversation.monitor.finish_transaction(prepared, committed: true)
      end
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
