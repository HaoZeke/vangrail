# frozen_string_literal: true

module Vangrail
  # Validation for the attack-composition section of a joint-risk artifact.
  module JointRiskArtifactThreats
    private

    def validate_threat_model!
      model = data['threat_model']
      unless model.is_a?(Hash) &&
             model.keys.sort == %w[covariance_diagonal log_likelihood_offsets training_composition]
        raise ProtocolError, 'threat_model must name composition, offsets, and covariance'
      end

      composition = model['training_composition']
      limit = JointRiskArtifact::MAX_THREAT_FAMILIES
      unless composition.is_a?(Hash) && composition.size.between?(1, limit) &&
             composition.keys.all? { |family| family.is_a?(String) && !family.empty? }
        raise ProtocolError, "training threat composition must contain 1..#{limit} families"
      end

      validate_numeric_table!('training threat composition', composition)
      unless composition.values.all?(&:positive?) && (composition.values.sum - 1.0).abs <= 1e-9
        raise ProtocolError, 'training threat composition must contain positive probabilities summing to one'
      end

      validate_numeric_table!('threat offsets', model['log_likelihood_offsets'],
                              allowed: composition.keys, exact: true)
      validate_numeric_table!('threat covariance', model['covariance_diagonal'],
                              allowed: composition.keys, exact: true, nonnegative: true)
    end
  end
end
