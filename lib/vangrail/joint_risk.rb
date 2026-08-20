# frozen_string_literal: true

require_relative 'joint_risk_artifact'
require_relative 'joint_risk_mixture_inference'
require_relative 'judgement'
require_relative 'result'
require_relative 'risk_scenario'
require_relative 'score'

module Vangrail
  # Calibrated posterior and interval emitted by a JointRiskModel.
  class RiskEstimate
    attr_reader :artifact_id, :posterior_method, :posterior, :interval,
                :calibration_id, :status, :reason, :features, :cost, :context

    def initialize(artifact_id:, posterior_method:, calibration_id:, status:,
                   posterior: nil, interval: nil, reason: nil, features: {},
                   cost: {}, context: {})
      @artifact_id = artifact_id.to_s.freeze
      @posterior_method = posterior_method.to_s.freeze
      @calibration_id = calibration_id.to_s.freeze
      @status = status.to_sym
      @posterior = posterior
      @interval = interval&.dup&.freeze
      @reason = reason&.to_s&.freeze
      @features = features.dup.freeze
      @cost = cost.dup.freeze
      @context = context.dup.freeze
      freeze
    end

    def valid?
      status == :ok
    end

    def abstained?
      status == :abstained
    end

    def certain?(policy)
      return false unless valid? && interval

      policy.action_for(interval.first) == policy.action_for(interval.last)
    end

    # Converts empirical risk into a restriction consumed by ReferenceMonitor.
    # An allow result never creates authority; it only declines to remove an
    # existing grant.
    def restriction(policy = Policy::DEFAULT)
      return Result.unchecked(rail: 'joint_risk', reason: reason, raw: to_h) if abstained?
      unless certain?(policy)
        return Result.unchecked(
          rail: 'joint_risk',
          reason: 'posterior interval crosses a policy boundary',
          raw: to_h,
        )
      end

      action = policy.action_for(posterior)
      return Result.passed(rail: 'joint_risk', raw: to_h) if action == :allow

      Result.blocked(rail: 'joint_risk', reason: "risk policy requires #{action}", raw: to_h)
    end

    def to_h
      {
        'artifact_id' => artifact_id,
        'posterior_method' => posterior_method,
        'calibration_id' => calibration_id,
        'status' => status.to_s,
        'posterior' => posterior,
        'interval' => interval,
        'features' => features,
        'cost' => cost,
        'context' => context,
        'reason' => reason,
      }.compact
    end
  end

  # Standard-library inference for a compact joint posterior approximation.
  class JointRiskModel
    include JointRiskMixtureInference

    class Abstention < StandardError; end

    CONTEXT_FIELDS = {
      side: 'sides',
      origin: 'origins',
      language: 'languages',
      domain: 'domains',
    }.freeze

    attr_reader :artifact

    def initialize(artifact)
      raise ArgumentError, 'artifact must be a JointRiskArtifact' unless artifact.is_a?(JointRiskArtifact)

      @artifact = artifact
    end

    def estimate(results, side:, origin:, language:, domain:, prior: nil, scenario: nil, confidence: 0.95)
      prior, scenario = resolve_scenario(prior, scenario)
      validate_probability!(prior, 'prior')
      validate_probability!(confidence, 'confidence')
      context = normalized_context(side: side, origin: origin, language: language, domain: domain)
      validate_context!(context)
      values = inference(results, side, context, prior, scenario, confidence)
      RiskEstimate.new(**artifact_identity, status: :ok, **values)
    rescue Abstention => e
      RiskEstimate.new(
        **artifact_identity,
        status: :abstained,
        reason: e.message,
        context: defined?(context) ? context : {},
      )
    end

    private

    def inference(results, side, context, prior, scenario, confidence)
      features, cost = collect_features(Array(results), side)
      validate_ranges!(features)
      eta, variance, threat_mixture = posterior_parameters(features, context, prior, scenario)
      radius = normal_quantile((1 + confidence) / 2.0) * Math.sqrt(variance)
      {
        posterior: logistic(eta),
        interval: [logistic(eta - radius), logistic(eta + radius)],
        features: features,
        cost: cost,
        context: estimate_context(context, prior, threat_mixture),
      }
    end

    def posterior_parameters(features, context, prior, scenario)
      eta = linear_predictor(features, context)
      variance = posterior_variance(features, context)
      eta, variance = calibrate(eta, variance)
      threat_shift, threat_variance, threat_mixture = threat_adjustment(scenario)
      eta += prior_offset(prior) + threat_shift
      variance += scenario_variance(scenario) + threat_variance
      [eta, variance, threat_mixture]
    end

    def artifact_identity
      {
        artifact_id: artifact.id,
        posterior_method: artifact.posterior_method,
        calibration_id: artifact.calibration.fetch('id'),
      }
    end

    def resolve_scenario(prior, scenario)
      raise ArgumentError, 'pass prior or scenario, not both' if prior && scenario
      return [prior, nil] unless scenario
      raise ArgumentError, 'scenario must be a RiskScenario' unless scenario.is_a?(RiskScenario)

      [scenario.prior, scenario]
    end

    def estimate_context(context, prior, threat_mixture)
      context.transform_keys(&:to_s).merge(
        'prevalence' => prior,
        'threat_mixture' => threat_mixture,
      ).freeze
    end

    def collect_features(results, side)
      features = {}
      used = []
      artifact.readers.each do |reader_id, spec|
        result = results.detect { |candidate| candidate.reader_id == reader_id }
        raise Abstention, "missing reader #{reader_id}" unless result
        raise Abstention, "reader #{reader_id} #{result.status}: #{result.reason}" unless result.valid?
        unless result.model_id == spec.fetch('model_id')
          raise Abstention, "reader #{reader_id} model identity does not match the artifact"
        end
        unless result.feature_schema == spec.fetch('feature_schema')
          raise Abstention, "reader #{reader_id} feature schema does not match the artifact"
        end
        raise Abstention, "reader #{reader_id} scored #{result.side}, not #{side}" unless result.side == side.to_sym

        result.scores.each { |name, value| features["#{reader_id}.#{name}"] = value }
        used << result
      end
      [features.freeze, aggregate_cost(used)]
    end

    def aggregate_cost(results)
      totals = results.each_with_object(Hash.new(0.0)) do |result, total|
        result.cost.each { |name, value| total[name] += value }
      end
      totals.transform_values { |value| value.to_i == value ? value.to_i : value }.freeze
    end

    def validate_ranges!(features)
      artifact.score_ranges.each do |name, (low, high)|
        value = features.fetch(name)
        next if value.between?(low, high)

        raise Abstention, "score #{name}=#{value} is outside the calibrated range #{low}..#{high}"
      end
    end

    def normalized_context(**values)
      values.transform_values(&:to_s).freeze
    end

    def validate_context!(context)
      CONTEXT_FIELDS.each do |field, support_name|
        value = context.fetch(field)
        next if artifact.supported.fetch(support_name).include?(value)

        raise Abstention, "unsupported #{field} #{value.inspect}"
      end
    end

    def linear_predictor(features, context)
      eta = artifact.intercept
      artifact.coefficients.each { |name, coefficient| eta += coefficient * features.fetch(name) }
      artifact.interactions.each do |name, coefficient|
        left, right = name.split('*', 2)
        eta += coefficient * features.fetch(left) * features.fetch(right)
      end
      context.each { |name, value| eta += artifact.context_offsets.fetch("#{name}:#{value}", 0.0) }
      eta
    end

    def calibrate(eta, variance)
      calibration = artifact.calibration
      return [eta, variance] if calibration.fetch('method') == 'identity'

      slope = calibration.fetch('slope')
      covariance = calibration.fetch('covariance_diagonal')
      calibrated_variance = ((slope**2) * variance) + covariance.fetch('intercept') +
                            ((eta**2) * covariance.fetch('slope'))
      [calibration.fetch('intercept') + (slope * eta), calibrated_variance]
    end

    def posterior_variance(features, context)
      covariance = artifact.covariance_diagonal
      variance = covariance.fetch('intercept', 0.0)
      artifact.feature_schema.each do |name|
        variance += covariance.fetch(name, 0.0) * (features.fetch(name)**2)
      end
      artifact.interactions.each_key do |name|
        left, right = name.split('*', 2)
        value = features.fetch(left) * features.fetch(right)
        variance += covariance.fetch(name, 0.0) * (value**2)
      end
      context.each do |name, value|
        variance += covariance.fetch("#{name}:#{value}", 0.0)
      end
      variance
    end

    def prior_offset(prior)
      logit(prior) - logit(artifact.training_prevalence)
    end

    def logit(probability)
      Math.log(probability / (1 - probability))
    end

    def logistic(value)
      return 1.0 / (1.0 + Math.exp(-value)) if value >= 0

      exp = Math.exp(value)
      exp / (1.0 + exp)
    end

    def validate_probability!(value, name)
      return if value.is_a?(Numeric) && value.finite? && value.positive? && value < 1

      raise ArgumentError, "#{name} must be finite and strictly between 0 and 1"
    end

    # Acklam's rational approximation of the inverse standard normal CDF.
    def normal_quantile(probability)
      a = [-39.696_830_286_653_8, 220.946_098_424_521, -275.928_510_446_969,
           138.357_751_867_269, -30.664_798_066_147_2, 2.506_628_277_459_24]
      b = [-54.476_098_798_224_1, 161.585_836_858_041, -155.698_979_859_887,
           66.801_311_887_719_7, -13.280_681_552_885_7]
      c = [-0.007_784_894_002_430_29, -0.322_396_458_041_136, -2.400_758_277_161_84,
           -2.549_732_539_343_73, 4.374_664_141_464_97, 2.938_163_982_698_78]
      d = [0.007_784_695_709_041_46, 0.322_467_129_070_04, 2.445_134_137_143,
           3.754_408_661_907_42]
      threshold = 0.02425
      return normal_tail(probability, c, d) if probability < threshold
      return -normal_tail(1 - probability, c, d) if probability > 1 - threshold

      q = probability - 0.5
      r = q * q
      polynomial(a, r) * q / ((polynomial(b, r) * r) + 1)
    end

    def normal_tail(probability, numerator, denominator)
      q = Math.sqrt(-2 * Math.log(probability))
      polynomial(numerator, q) / ((polynomial(denominator, q) * q) + 1)
    end

    def polynomial(coefficients, value)
      coefficients.drop(1).reduce(coefficients.first) { |sum, coefficient| (sum * value) + coefficient }
    end
  end
end
