# frozen_string_literal: true

require 'securerandom'
require_relative 'errors'
require_relative 'origin'

module Vangrail
  # One scoped authority in a Plan.
  class Grant
    EFFECTS = %i[read write external].freeze

    attr_reader :id, :tool, :effect, :arguments, :sinks, :uses, :after,
                :integrity, :conversation_id

    def initialize(tool:, effect:, arguments: {}, sinks: nil, uses: nil, after: nil,
                   integrity: nil, confirm: false, transaction: false,
                   conversation_id: nil, id: nil)
      @tool = tool.to_sym
      @effect = effect.to_sym
      raise ArgumentError, "effect must be one of #{EFFECTS.join(', ')}" unless EFFECTS.include?(@effect)
      if !uses.nil? && (!uses.is_a?(Integer) || !uses.positive?)
        raise ArgumentError, 'uses must be a positive integer or nil'
      end

      @id = (id || SecureRandom.uuid).to_s.freeze
      @arguments = immutable_hash(arguments)
      @sinks = normalize_optional(sinks)
      @uses = uses
      @after = normalize(after)
      @integrity = normalize_optional(integrity)
      @confirmation_required = confirm.equal?(true)
      @transaction_required = transaction.equal?(true)
      @conversation_id = conversation_id&.to_s&.freeze
      freeze
    end

    def confirmation_required?
      @confirmation_required
    end

    def transaction_required?
      @transaction_required
    end

    def to_h
      {
        'id' => id,
        'tool' => tool.to_s,
        'effect' => effect.to_s,
        'arguments' => arguments.transform_values { |constraint| describe(constraint) },
        'sinks' => sinks&.map(&:to_s),
        'uses' => uses,
        'after' => after.map(&:to_s),
        'integrity' => integrity&.map(&:to_s),
        'confirm' => confirmation_required?,
        'transaction' => transaction_required?,
        'conversation_id' => conversation_id,
      }.compact
    end

    private

    def immutable_hash(value)
      raise ArgumentError, 'arguments must be a hash' unless value.is_a?(Hash)

      value.each_with_object({}) do |(name, constraint), copy|
        copy[name.to_sym] = immutable(constraint)
      end.freeze
    end

    def immutable(value)
      case value
      when Hash then immutable_hash(value)
      when Array then value.map { |item| immutable(item) }.freeze
      when String then value.dup.freeze
      else
        value.freeze
      end
    end

    def normalize(values)
      Array(values).map(&:to_sym).uniq.freeze
    end

    def normalize_optional(values)
      values.nil? ? nil : normalize(values)
    end

    def describe(value)
      case value
      when Cell then value.to_h
      when Hash then value.transform_values { |nested| describe(nested) }
      when Array then value.map { |nested| describe(nested) }
      else value
      end
    end
  end

  # Privileged, lockable collection of grants for one conversation.
  class Plan
    attr_reader :id

    def initialize(id: nil)
      @id = (id || SecureRandom.uuid).to_s.freeze
      @grants = []
      @locked = false
    end

    def read(tool, **options)
      add(tool, :read, **options)
    end

    def write(tool, **options)
      add(tool, :write, **options)
    end

    def external(tool, **options)
      add(tool, :external, **options)
    end

    def grants
      @grants.dup.freeze
    end

    def grants_for(tool)
      name = tool.to_sym
      @grants.select { |grant| grant.tool == name }.freeze
    end

    def grant_for(tool)
      grants_for(tool).first
    end

    def lock!
      @grants.freeze
      @locked = true
      self
    end

    def locked?
      @locked
    end

    def to_h
      { 'id' => id, 'locked' => locked?, 'grants' => @grants.map(&:to_h) }
    end

    def self.from_allow(allow, tools:, id: nil)
      new(id: id).tap do |plan|
        allow.each do |tool, origins|
          next unless tools.readonly?(tool)

          allowed = Array(origins).map(&:to_sym)
          arguments = if allowed.empty?
                        {}
                      else
                        { value: allowed.one? ? allowed.first : allowed }
                      end
          plan.read(tool, arguments: arguments)
        end
      end
    end

    private

    def add(tool, effect, **options)
      raise PrivilegeError, 'the plan is locked' if locked?

      Grant.new(tool: tool, effect: effect, conversation_id: id, **options).tap do |grant|
        @grants << grant
      end
    end
  end
end
