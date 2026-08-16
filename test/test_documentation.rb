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
  # [path relative to the repo root, first line of the block, reason].
  NEEDS_NETWORK = [
    ['docs/orgmode/howto/calibrating-a-model-rail.org',
     'Vangrail.provider.name        # => "llmlite"',
     'probes a live provider'],
    ['docs/orgmode/howto/calibrating-a-model-rail.org',
     'engine = Vangrail.from_env',
     'checks a configured semantic rail against a live page'],
    ['docs/orgmode/howto/choosing-an-endpoint.org',
     'Vangrail::Providers.register_gateway(',
     'registers a live gateway'],
    ['README.md',
     'Vangrail::Providers.register_gateway(',
     'registers a live gateway'],
    ['README.md',
     'Vangrail.provider.name        # => "llmlite"',
     'probes a live provider'],
    ['README.md',
     'Vangrail::Provider.register(',
     'registers a live endpoint'],
    ['README.md',
     "config = Vangrail::Config.load('config/handbook')",
     'loads a folder against the resolved provider'],
    ['README.md',
     "Vangrail::Config.for_provider(Vangrail.provider, name: 'handbook').write!('config')",
     'writes a folder from the resolved provider'],
    ['README.md',
     "client = Vangrail.client(base_url: 'http://127.0.0.1:8000', config_id: 'handbook')",
     'talks to a Guardrails server'],
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
    path.sub(%r{\A#{Regexp.escape(ROOT)}/?}, '')
  end

  def first_line(source)
    source.lines.first.to_s.strip
  end

  def network_reason(path, source)
    line = first_line(source)
    name = rel(path)
    NEEDS_NETWORK.detect { |listed, first, _reason| listed == name && first == line }&.last
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
    missing = NEEDS_NETWORK.reject do |listed, first, _reason|
      path = File.join(ROOT, listed)
      File.file?(path) && ruby_blocks(path).any? { |src| first_line(src) == first }
    end

    assert_empty missing, "NEEDS_NETWORK names blocks that are not in the documents:\n  #{missing.inspect}"
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
