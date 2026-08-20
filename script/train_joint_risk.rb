#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative 'joint_risk_cli'

exit Vangrail::JointRiskTrainingCli.run(ARGV)
