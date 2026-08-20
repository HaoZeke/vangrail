#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative 'agent_dojo_import_cli'

exit Vangrail::AgentDojoImportCli.run(ARGV)
