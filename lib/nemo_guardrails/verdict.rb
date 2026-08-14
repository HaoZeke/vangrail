# frozen_string_literal: true

module NemoGuardrails
  # One rail's decision about one piece of text.
  #
  # `allowed` carries the decision; `certain` says whether a rail actually
  # produced it. An unreachable guard model yields allowed=true, certain=false,
  # which is the difference between "checked and clean" and "not checked".
  # Callers that must not overstate their safety posture read `certain`.
  class Verdict
    ALLOW = :allow
    BLOCK = :block

    attr_reader :rail, :reason, :categories, :model, :latency_ms, :raw

    def initialize(allowed:, rail:, certain: true, reason: nil, categories: [], model: nil,
                   latency_ms: nil, raw: nil)
      @allowed = allowed
      @certain = certain
      @rail = rail
      @reason = reason
      @categories = Array(categories)
      @model = model
      @latency_ms = latency_ms
      @raw = raw
    end

    def self.allow(rail:, **kwargs)
      new(allowed: true, rail: rail, **kwargs)
    end

    def self.block(rail:, **kwargs)
      new(allowed: false, rail: rail, **kwargs)
    end

    # No rail ran. Allowed, but explicitly not vouched for.
    def self.unchecked(rail:, reason:)
      new(allowed: true, rail: rail, certain: false, reason: reason)
    end

    def allowed?
      @allowed
    end

    def blocked?
      !@allowed
    end

    # A rail reached a decision, as opposed to being skipped or failing open.
    def certain?
      @certain
    end

    def decision
      allowed? ? ALLOW : BLOCK
    end

    def to_h
      {
        'decision' => decision.to_s,
        'certain' => certain?,
        'rail' => rail.to_s,
        'reason' => reason,
        'categories' => categories,
        'model' => model,
        'latency_ms' => latency_ms
      }.compact
    end

    def to_s
      parts = ["#{rail}=#{decision}"]
      parts << 'unchecked' unless certain?
      parts << categories.join(',') unless categories.empty?
      parts << reason if reason
      parts.join(' ')
    end
  end
end
