# frozen_string_literal: true

require_relative 'beta'

module Vangrail
  # Immutable beta-binomial prevalence supplied by a deployment or evaluation.
  class BetaBinomialPrior
    attr_reader :alpha, :beta

    def initialize(alpha:, beta:)
      @alpha = positive(alpha, 'alpha')
      @beta = positive(beta, 'beta')
      freeze
    end

    def mean
      alpha.fdiv(alpha + beta)
    end

    def interval(confidence: 0.95)
      probability(confidence, 'confidence')
      tail = (1 - confidence) / 2.0
      [Beta.quantile(tail, alpha, beta), Beta.quantile(1 - tail, alpha, beta)].freeze
    end

    def adjudicate(label)
      case label.to_sym
      when :attack then self.class.new(alpha: alpha + 1, beta: beta)
      when :benign then self.class.new(alpha: alpha, beta: beta + 1)
      else raise ArgumentError, "unknown adjudicated label #{label.inspect}"
      end
    end

    def to_h
      { 'alpha' => alpha, 'beta' => beta, 'mean' => mean }.freeze
    end

    private

    def positive(value, name)
      number = Float(value)
      return number if number.positive? && number.finite?

      raise ArgumentError, "#{name} must be finite and positive"
    rescue TypeError
      raise ArgumentError, "#{name} must be finite and positive"
    end

    def probability(value, name)
      return if value.is_a?(Numeric) && value.finite? && value.positive? && value < 1

      raise ArgumentError, "#{name} must be finite and strictly between 0 and 1"
    end
  end

  # Immutable Dirichlet posterior over named attack families.
  class DirichletThreatPrior
    attr_reader :concentrations

    def initialize(values = nil, **families)
      raise ArgumentError, 'pass threat concentrations once' if values && !families.empty?

      raw = values || families
      unless raw.is_a?(Hash) && !raw.empty?
        raise ArgumentError, 'threat concentrations must be a nonempty hash'
      end

      @concentrations = raw.to_h do |family, concentration|
        [family.to_s.freeze, positive(concentration, family)]
      end.freeze
      freeze
    end

    def mean
      total = concentrations.values.sum
      concentrations.to_h { |family, value| [family, value.fdiv(total)] }.freeze
    end

    def intervals(confidence: 0.95)
      validate_confidence!(confidence)
      total = concentrations.values.sum
      tail = (1 - confidence) / 2.0
      concentrations.to_h do |family, value|
        bounds = [Beta.quantile(tail, value, total - value),
                  Beta.quantile(1 - tail, value, total - value)].freeze
        [family, bounds]
      end.freeze
    end

    def adjudicate(family)
      name = family.to_s
      raise ArgumentError, "unknown threat family #{family.inspect}" unless concentrations.key?(name)

      self.class.new(concentrations.merge(name => concentrations.fetch(name) + 1))
    end

    def to_h
      { 'concentrations' => concentrations, 'mean' => mean }.freeze
    end

    private

    def positive(value, family)
      number = Float(value)
      return number if number.positive? && number.finite?

      raise ArgumentError, "threat concentration #{family.inspect} must be finite and positive"
    rescue TypeError
      raise ArgumentError, "threat concentration #{family.inspect} must be finite and positive"
    end

    def validate_confidence!(value)
      return if value.is_a?(Numeric) && value.finite? && value.positive? && value < 1

      raise ArgumentError, 'confidence must be finite and strictly between 0 and 1'
    end
  end

  # Deployment assumptions changed only by externally adjudicated outcomes.
  class RiskScenario
    attr_reader :prevalence, :threats

    def initialize(prevalence:, threats:)
      unless prevalence.is_a?(BetaBinomialPrior) && threats.is_a?(DirichletThreatPrior)
        raise ArgumentError, 'scenario needs beta-binomial prevalence and Dirichlet threats'
      end

      @prevalence = prevalence
      @threats = threats
      freeze
    end

    def prior
      prevalence.mean
    end

    def threat_mixture
      threats.mean
    end

    def adjudicate(label:, family: nil)
      case label.to_sym
      when :attack
        raise ArgumentError, 'an adjudicated attack needs a threat family' if family.nil?

        self.class.new(prevalence: prevalence.adjudicate(:attack), threats: threats.adjudicate(family))
      when :benign
        raise ArgumentError, 'a benign adjudication cannot name a threat family' unless family.nil?

        self.class.new(prevalence: prevalence.adjudicate(:benign), threats: threats)
      else
        raise ArgumentError, "unknown adjudicated label #{label.inspect}"
      end
    end

    def to_h
      { 'prevalence' => prevalence.to_h, 'threats' => threats.to_h }.freeze
    end
  end
end
