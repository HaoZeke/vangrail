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

  # Blocks that cannot run here and say so: they need an endpoint, a key, or a
  # server. A regex would skip a new snippet without naming it. Each entry is
  # [path relative to the repo root, a line unique to the block, reason].
  #
  # The line is not always the first. Three tutorial blocks start with
  # `require 'vangrail'`, and only the README one calls from_env. Matching on
  # the first line would skip the two that never open a socket.
  #
  # register_gateway and Provider.register are not listed: they install a
  # struct. No socket opens until something later asks the registry to
  # resolve.
  NEEDS_NETWORK = [
    ['README.md',
     'engine = Vangrail.from_env',
     'resolves a provider and may call a live model'],
  ].freeze

  def setup
    isolate_env!
  end

  def teardown
    restore_env!
  end

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

  def rel(path)
    path.sub(/\A#{Regexp.escape(ROOT)}\/?/o, '')
  end

  def first_line(source)
    source.lines.first.to_s.strip
  end

  def network_reason(path, source)
    name = rel(path)
    NEEDS_NETWORK.detect { |listed, marker, _reason| listed == name && source.include?(marker) }&.last
  end

  def live_call?(source)
    source.include?('Vangrail.from_env') ||
      source.match?(/Vangrail(?:\.client|::Client\.new)\b/)
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
                       .map { |src| "#{rel(path)}: #{first_line(src)}" }
    end

    assert_empty broken, "these blocks do not parse:\n  #{broken.join("\n  ")}"
  end

  def test_the_network_list_names_real_blocks
    missing = NEEDS_NETWORK.reject do |listed, marker, _reason|
      path = File.join(ROOT, listed)
      File.file?(path) && ruby_blocks(path).any? { |src| src.include?(marker) }
    end

    assert_empty missing, "NEEDS_NETWORK names blocks that are not in the documents:\n  #{missing.inspect}"
  end

  def test_every_self_contained_live_example_is_named
    unnamed = documents.flat_map do |path|
      ruby_blocks(path).select { |src| src.include?("require 'vangrail'") && live_call?(src) }
                       .reject { |src| network_reason(path, src) }
                       .map { |src| "#{rel(path)}: #{first_line(src)}" }
    end

    message = "these self-contained examples call from_env or Client " \
              "and are not in NEEDS_NETWORK:\n  #{unnamed.join("\n  ")}"
    assert_empty unnamed, message
  end

  def self_contained
    documents.flat_map do |path|
      ruby_blocks(path).select { |src| src.include?("require 'vangrail'") }
                       .reject { |src| network_reason(path, src) }
                       .map { |src| [rel(path), src] }
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
