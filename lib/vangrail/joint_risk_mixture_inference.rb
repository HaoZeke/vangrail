# frozen_string_literal: true

module Vangrail
  # Attack-composition odds and uncertainty for joint-risk inference.
  module JointRiskMixtureInference
    private

    def threat_adjustment(scenario)
      model = artifact.threat_model
      training = model.fetch('training_composition')
      deployment = scenario ? scenario.threat_mixture : training
      unless deployment.keys.sort == training.keys.sort
        raise JointRiskModel::Abstention, 'deployment threat families do not match the artifact'
      end

      offsets = model.fetch('log_likelihood_offsets')
      training_weight = mixture_weight(training, offsets)
      deployment_weight = mixture_weight(deployment, offsets)
      shift = Math.log(deployment_weight / training_weight)
      variance = offset_mixture_variance(training, deployment, offsets, model.fetch('covariance_diagonal'))
      variance += composition_variance(scenario, deployment, offsets, deployment_weight) if scenario
      [shift, variance, deployment]
    end

    def mixture_weight(mixture, offsets)
      mixture.sum { |family, probability| probability * Math.exp(offsets.fetch(family)) }
    end

    def offset_mixture_variance(training, deployment, offsets, covariance)
      training_weight = mixture_weight(training, offsets)
      deployment_weight = mixture_weight(deployment, offsets)
      offsets.sum do |family, value|
        training_share = training.fetch(family) * Math.exp(value) / training_weight
        deployment_share = deployment.fetch(family) * Math.exp(value) / deployment_weight
        ((deployment_share - training_share)**2) * covariance.fetch(family)
      end
    end

    def composition_variance(scenario, mixture, offsets, weight)
      concentration = scenario.threats.concentrations.values.sum
      second_moment = mixture.sum do |family, probability|
        gradient = Math.exp(offsets.fetch(family)) / weight
        probability * (gradient**2)
      end
      [(second_moment - 1.0) / (concentration + 1.0), 0.0].max
    end

    def scenario_variance(scenario)
      return 0.0 unless scenario

      prior = scenario.prior
      concentration = scenario.prevalence.alpha + scenario.prevalence.beta
      1.0 / ((concentration + 1.0) * prior * (1 - prior))
    end
  end
end
