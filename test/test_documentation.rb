# frozen_string_literal: true

require_relative 'helper'
require 'open3'

# The documentation is executable, and this is what makes that true.
#
# A tutorial whose output is wrong is worse than no tutorial: the reader assumes
# they broke it, and the second thing they conclude is that the rest of the
# documentation is decorative too. Prose drifts from an API silently. Code does
# not, if somebody runs it.
#
# Two levels, because they catch different rot:
#
#   every Ruby block must parse        catches a typo, an unclosed string, a
#                                      snippet mangled while editing prose
#   self-contained blocks must run     catches a renamed method, a changed
#                                      default, a class that no longer exists
#
# A block counts as self-contained when it requires the library itself. Those
# are the ones a reader copies whole and expects to work, so those are the ones
# held to the higher standard. Fragments are still parsed.
class TestDocumentation < Minitest::Test
  include GuardrailsTest

  ROOT = File.expand_path('..', __dir__)

  # Blocks that cannot run here and say so in the document itself: they need an
  # endpoint, a key, or a server. Skipping them silently would be the wrong
  # trade, so each is listed with the reason.
  NEEDS_NETWORK = /Vangrail\.provider|provider:|base_url:|Client\.new|GUARDRAILS_API|chat:|Chat\.new/

  def documents
    Dir[File.join(ROOT, 'docs', '**', '*.org')] + [File.join(ROOT, 'README.md')]
  end

  # Org and markdown fences, with the language tag Ruby blocks carry.
  def ruby_blocks(path)
    text = File.read(path)
    org = text.scan(/^\s*#\+begin_src ruby[^\n]*\n(.*?)^\s*#\+end_src/mi)
    md = text.scan(/^```ruby\n(.*?)^```/m)
    (org + md).flatten.map(&:strip).reject(&:empty?)
  end

  def parses?(source)
    RubyVM::InstructionSequence.compile(source)
    true
  rescue SyntaxError
    false
  end

  def test_every_documented_ruby_block_parses
    broken = documents.flat_map do |path|
      ruby_blocks(path).reject { |src| parses?(src) }
                       .map { |src| "#{File.basename(path)}: #{src.lines.first.to_s.strip}" }
    end

    assert_empty broken, "these blocks do not parse:\n  #{broken.join("\n  ")}"
  end

  def self_contained
    documents.flat_map do |path|
      ruby_blocks(path).select { |src| src.include?("require 'vangrail'") }
                       .grep_v(NEEDS_NETWORK)
                       .map { |src| [File.basename(path), src] }
    end
  end

  def test_the_documentation_has_blocks_worth_running
    refute_empty self_contained, 'no self-contained example was found to run'
  end

  def test_every_self_contained_example_runs
    failures = self_contained.filter_map do |(name, source)|
      out, status = Open3.capture2e(RbConfig.ruby, '-I', File.join(ROOT, 'lib'), '-e', source)
      next if status.success?

      "#{name}: #{out.lines.reject { |l| l.include?('warning:') }.first(3).join.strip}"
    end

    assert_empty failures, "these documented examples do not run:\n  #{failures.join("\n  ")}"
  end
end
