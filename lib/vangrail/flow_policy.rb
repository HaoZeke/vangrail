# frozen_string_literal: true

require_relative 'audit'
require_relative 'errors'
require_relative 'origin'

module Vangrail
  # Named, audited authority for integrity endorsement and sink declassification.
  class FlowPolicy
    attr_reader :audit

    def initialize(endorsements: {}, declassifications: {}, audit: nil)
      @endorsements = normalize_rules(endorsements, required: :integrity)
      @declassifications = normalize_rules(declassifications, required: :sinks)
      @audit = audit || AuditLog.new
      freeze
    end

    def endorse(operation, cell, actor:)
      rule = fetch_rule(@endorsements, operation)
      validate_actor!(actor, rule)
      validate_cell!(cell)

      label = Label.new(
        provenance: cell.origins + actor.origins,
        integrity: rule.fetch(:integrity),
        confidentiality: cell.confidentiality,
        capabilities: cell.capabilities,
      )
      Cell.new(cell.raw, label: label).tap do |output|
        audit.record(:endorsement, operation: operation, actor: actor, input: cell, output: output)
      end
    end

    def declassify(operation, cell, actor:)
      rule = fetch_rule(@declassifications, operation)
      validate_actor!(actor, rule)
      validate_cell!(cell)

      label = Label.new(
        provenance: cell.origins + actor.origins,
        integrity: cell.integrity,
        confidentiality: rule.fetch(:sinks),
        capabilities: cell.capabilities,
      )
      Cell.new(cell.raw, label: label).tap do |output|
        audit.record(:declassification, operation: operation, actor: actor,
                                        input: cell, output: output)
      end
    end

    private

    def normalize_rules(rules, required:)
      rules.each_with_object({}) do |(name, raw_rule), normalized|
        rule = raw_rule.transform_keys(&:to_sym)
        raise ArgumentError, "#{name} requires #{required}" unless rule.key?(required)

        normalized[name.to_sym] = {
          actors: Array(rule.fetch(:actors)).map(&:to_sym).uniq.freeze,
          required => Array(rule.fetch(required)).map(&:to_sym).uniq.freeze,
        }.freeze
      end.freeze
    end

    def fetch_rule(rules, operation)
      rules.fetch(operation.to_sym)
    rescue KeyError
      raise PrivilegeError, "flow operation #{operation} is not granted"
    end

    def validate_actor!(actor, rule)
      validate_cell!(actor)
      allowed = actor.privileged? && actor.origins.all? { |origin| rule[:actors].include?(origin.kind) }
      raise PrivilegeError, 'flow operation requires an authorized privileged actor' unless allowed
    end

    def validate_cell!(cell)
      raise ArgumentError, 'flow operations require Cells' unless cell.is_a?(Cell)
    end
  end
end
