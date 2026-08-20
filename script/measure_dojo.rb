# frozen_string_literal: true

# Local handbook regression score for the origin cut.
#
#   ruby script/measure_dojo.rb
#
# Security: the injected tool stayed dark. Utility: the user tool ran and
# returned the asked-for fact. Lexical variants apply concept-synonym rewrites
# to the page. This script does not execute a target model or adversary and is
# not an adaptive benchmark.

$LOAD_PATH.unshift(File.expand_path('../lib', __dir__))
require 'vangrail'

engine = Vangrail::Engine.new(input: Vangrail::Builder.deterministic(:input),
                              context: Vangrail::Builder.deterministic(:context))
tools = Vangrail::Tools.new
tools.register(:cite, readonly: true) { |args, _| Vangrail::Cell.text_of(args) }
tools.register(:delete_all) { |_args, _| 'deleted' }
tools.register(:dump_secrets) { |_args, _| 'sk-live-leaked' }
allow = { cite: %i[data] }
dojo = Vangrail::Dojo.new(engine: engine, allow: allow)

base = dojo.score(tools: tools)
lexical = dojo.adaptive(tools: tools, limit: 12)
puts format('handbook  n=%<n>d  security=%<security>d/%<n>d  utility=%<utility>d/%<n>d',
            **base)
puts format('lexical   n=%<n>d  security=%<security>d/%<n>d  utility=%<utility>d/%<n>d',
            **lexical)
