# frozen_string_literal: true

require_relative 'errors'

module Vangrail
  # A named, session-pinned posture. Copied from Grok Build's sandbox
  # and permission model, not from a detector paper.
  #
  # Grok Build pins the sandbox profile for the life of a session and
  # refuses to change it on resume. Deny rules still apply under
  # always-approve. Child processes do not inherit KEY/SECRET/TOKEN.
  # The same four facts live here:
  #
  #   Profile.workspace   cite and search; mutating names are denied
  #   Profile.strict      cite only; only read-only tools
  #   Profile.read_only   no invoke of a mutating tool
  #   Profile.off         no grants
  #
  # The profile is chosen at Conversation construction and cannot be
  # widened later. Deny always wins over allow and over the plan.
  class Profile
    NAMES = %i[off read_only workspace strict].freeze
    SECRET = /key|secret|token|password|passwd|authorization/i

    attr_reader :name, :allow, :deny, :readonly, :strip_secrets

    def initialize(name:, allow: {}, deny: [], readonly: false, strip_secrets: true)
      @name = name.to_sym
      @allow = allow.transform_keys(&:to_sym)
                    .transform_values { |kinds| Array(kinds).map(&:to_sym) }
                    .freeze
      @deny = Array(deny).map { |rule| rule.to_s.freeze }.freeze
      @readonly = readonly
      @strip_secrets = strip_secrets
    end

    def readonly?
      @readonly
    end

    def strip_secrets?
      @strip_secrets
    end

    def denied?(tool)
      needle = tool.to_s
      deny.any? { |rule| File.fnmatch?(rule, needle, File::FNM_EXTGLOB) }
    end

    def self.off
      new(name: :off, allow: {}, deny: [], readonly: true)
    end

    def self.read_only
      new(name: :read_only, allow: {}, deny: [], readonly: true)
    end

    def self.workspace
      new(name: :workspace,
          allow: { cite: %i[data], search: [] },
          deny: %w[delete_* dump_* shell],
          readonly: false)
    end

    def self.strict
      new(name: :strict,
          allow: { cite: %i[data] },
          deny: %w[delete_* dump_* shell],
          readonly: true)
    end

    def self.resolve(value, allow: {}, deny: [])
      return value if value.is_a?(self)
      return from_allow(allow, deny: deny) if value.nil?

      case value.to_sym
      when :off then off
      when :read_only then read_only
      when :workspace then workspace
      when :strict then strict
      else raise ArgumentError, "unknown profile #{value.inspect}"
      end
    end

    def self.from_allow(allow, deny: [])
      new(name: :custom, allow: allow, deny: deny, readonly: false, strip_secrets: true)
    end

    def self.strip_secrets(env)
      env.each_with_object({}) do |(key, value), kept|
        next if key.to_s.match?(SECRET)

        kept[key] = value
      end
    end
  end
end
