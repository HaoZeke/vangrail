# frozen_string_literal: true

module Vangrail
  # What a rail decided about one piece of text.
  #
  # Three statuses, matching the contract the upstream toolkit settled on for
  # standalone rail checks:
  #
  #   :passed    the text is cleared and unchanged
  #   :modified  a rail rewrote the text; `content` carries the rewrite
  #   :blocked   a rail stopped the turn; `content` carries the refusal, if any
  #
  # Two states would be one too few. A rail that redacts a token from an answer
  # has neither passed the text nor blocked the turn, and folding that into
  # either one loses the fact that the reader is looking at edited output.
  #
  # `certain` is orthogonal to status. A rail that is off, not enabled, or
  # unreachable returns :passed with certain false, which is the difference
  # between "checked and clean" and "not checked". Callers that report a safety
  # posture read it; callers that only route on the decision can ignore it.
  class Result
    STATUSES = %i[passed modified blocked].freeze

    attr_reader :status, :rail, :content, :reason, :categories, :model, :latency_ms, :raw

    def initialize(status:, rail:, content: nil, reason: nil, categories: [], model: nil,
                   latency_ms: nil, raw: nil, certain: true)
      status = status.to_sym
      raise ArgumentError, "status must be one of #{STATUSES.join(', ')}" unless STATUSES.include?(status)

      @status = status
      @rail = rail
      @content = content
      @reason = reason
      @categories = Array(categories)
      @model = model
      @latency_ms = latency_ms
      @raw = raw
      @certain = certain
    end

    def self.passed(rail:, **kwargs)
      new(status: :passed, rail: rail, **kwargs)
    end

    def self.modified(rail:, content:, **kwargs)
      new(status: :modified, rail: rail, content: content, **kwargs)
    end

    def self.blocked(rail:, **kwargs)
      new(status: :blocked, rail: rail, **kwargs)
    end

    # No rail ran. Allowed, and explicitly not vouched for.
    def self.unchecked(rail:, reason:, **kwargs)
      new(status: :passed, rail: rail, certain: false, reason: reason, **kwargs)
    end

    def passed?
      status == :passed
    end

    def modified?
      status == :modified
    end

    def blocked?
      status == :blocked
    end

    def allowed?
      !blocked?
    end

    def certain?
      @certain
    end

    # The text to carry forward: the rewrite when there is one, otherwise what
    # the caller passed in.
    def content_or(original)
      modified? && !content.nil? ? content : original
    end

    # A copy with a different rail name, for an engine reporting which of its
    # rails produced a decision.
    def with_rail(name)
      self.class.new(
        status: status, rail: name, content: content, reason: reason, categories: categories,
        model: model, latency_ms: latency_ms, raw: raw, certain: certain?
      )
    end

    def to_h
      {
        'status' => status.to_s,
        'certain' => certain?,
        'rail' => rail&.to_s,
        'reason' => reason,
        'categories' => (categories unless categories.empty?),
        'model' => model,
        'latency_ms' => latency_ms,
      }.compact
    end

    def to_s
      parts = ["#{rail}=#{status}"]
      parts << 'unchecked' unless certain?
      parts << categories.join(',') unless categories.empty?
      parts << reason if reason
      parts.join(' ')
    end
  end
end
