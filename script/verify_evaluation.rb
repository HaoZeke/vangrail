#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative 'statistical_verifier_cli'

exit Vangrail::StatisticalVerifierCli.run(ARGV)
