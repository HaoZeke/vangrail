# frozen_string_literal: true

require_relative 'helper'

# The reference, resolved against the code rather than believed.
#
# `test_documentation.rb` runs the documentation: it parses every Ruby block and
# executes the self-contained ones. That catches a renamed method and a changed
# default. It cannot catch prose naming something that does not exist, because
# prose does not run, and the reference pages are almost entirely prose: a table
# of environment variables and a list of rail names.
#
# So this resolves both, both ways. A variable the library reads and the table
# does not name is a variable nobody can find. A variable the table names and
# nothing reads is an instruction to set something that does nothing, which is
# worse: the reader does the work and concludes the library is broken.
class TestReference < Minitest::Test
  ROOT = File.expand_path('..', __dir__)
  ENVIRONMENT_DOC = File.join(ROOT, 'docs', 'orgmode', 'reference', 'environment.org')

  # Sources that decide what a deployment can set. `script/` is deliberately
  # out: those files carry their own knobs (PAGES, PROMPTS, REPEATS) and the
  # reference documents the library.
  SOURCES = (Dir[File.join(ROOT, 'lib', '**', '*.rb')] + Dir[File.join(ROOT, 'exe', '*')]).freeze

  # Only the families the reference is about. A variable like HOME is read by
  # nobody here, and a test that policed every name in the standard library
  # would be policing Ruby.
  FAMILIES = /\A(?:GUARDRAILS|LLMLITE|GROK)(?:_|\z)/

  # `ENV['NAME']`, `ENV.fetch('NAME'`, and the same through a passed-in `env`
  # hash, which is how the builder reads its own copy.
  LITERAL = /\b(?:ENV|env)(?:\.fetch\(|\[)\s*['"]([A-Z][A-Z0-9_]*)['"]/.freeze

  # `"#{ENV_PREFIX}_API_BASE"`, anywhere rather than only inside `env[...]`.
  # The gateway composes eight names this way and hands three of them to a Spec
  # field instead of reading them on the spot, so a scanner watching only
  # `env[...]` reports those three as documented-but-unread, gets a reputation
  # for crying wolf, and is deleted. A composed name is an env name here by
  # construction: nothing else in this library builds an upper-case suffix onto
  # a prefix.
  INTERPOLATED = /"\#\{([A-Za-z_][A-Za-z0-9_]*)\}([A-Z0-9_]*)"/.freeze

  # Reads whose name is not fixed at all, one per registered provider or per
  # configured credential variable. They cannot be compared against a table of
  # names, so the reference has to document the pattern and this has to name
  # each site: a new one fails the run rather than widening the exemption
  # silently. [path, expression, what it generates].
  PATTERNS = [
    ['lib/vangrail/provider.rb', '#{env_prefix}_API_BASE',
     'one per registered provider, from its name upcased'],
    ['lib/vangrail/provider.rb', '#{env_prefix}_API_KEY',
     'one per registered provider, from its name upcased'],
    ['lib/vangrail/providers/gateway.rb', '#{spec.key_env}_FILE',
     'the _FILE suffix on whichever key variable a spec names'],
  ].freeze

  # The sentence in the reference that carries the pattern above. Asserted by
  # presence, because a pattern cannot be resolved into names to compare.
  PATTERN_MARKER = 'Every registered provider also reads'

  # That section illustrates the pattern with a real provider name, so it holds
  # variable names that no line reads literally and that no deployment can be
  # told to set. Read out of the comparison rather than exempted by shape: an
  # exemption on `_API_BASE` would also excuse a table row that went stale.
  PATTERN_SECTION = /^\*\* Overriding a provider by its own name.*?(?=^\*\* )/m.freeze

  # A constant assigned a plain string, which is the only interpolation this
  # resolves. Anything else fails the run rather than being skipped.
  CONSTANT = /^\s*([A-Z][A-Z0-9_]*)\s*=\s*['"]([^'"]+)['"]/.freeze

  # `=NAME=` inside the tables. Org verbatim markup, so the delimiters are the
  # column the reader sees.
  DOCUMENTED = /=([A-Z][A-Z0-9_]*)=/.freeze

  # Comment lines carry example variables belonging to whatever embeds this gem:
  # `ENV['ASK_WATERMARK_KEY']` appears twice as the desk's own name. A comment
  # is not a read. Numbered before filtering, so a failure names the line the
  # editor will open rather than the line's position in a filtered copy.
  def code_lines(path)
    File.readlines(path).each_with_index.reject { |(line, _number)| line.match?(/\A\s*#/) }
  end

  def resolvable_constants(path)
    File.read(path).scan(CONSTANT).to_h
  end

  # [names, unresolved sites]. Both are returned so the unresolved ones can fail
  # their own test instead of silently narrowing this one.
  def scan
    names = []
    unresolved = []
    SOURCES.each do |path|
      constants = resolvable_constants(path)
      code_lines(path).each do |(line, index)|
        names.concat(line.scan(LITERAL).flatten)
        line.scan(INTERPOLATED).each do |(const, suffix)|
          value = constants[const]
          next names << "#{value}#{suffix}" if value

          rel = path.sub("#{ROOT}/", '')
          next if listed_pattern?(rel, const, suffix)

          unresolved << "#{rel}:#{index + 1}: \#{#{const}}#{suffix}"
        end
      end
    end
    [names.uniq.grep(FAMILIES).sort, unresolved]
  end

  def listed_pattern?(rel, const, suffix)
    PATTERNS.any? { |(path, expression, _reason)| path == rel && expression == "\#{#{const}}#{suffix}" }
  end

  def code_variables
    @code_variables ||= scan.first
  end

  def documented_variables
    @documented_variables ||=
      File.read(ENVIRONMENT_DOC).sub(PATTERN_SECTION, '').scan(DOCUMENTED).flatten.uniq.grep(FAMILIES).sort
  end

  # The sentence the rail names live in. Named rather than globbed: if it is
  # reworded, this fails and somebody re-reads it, which is the point.
  def documented_rail_names
    text = File.read(ENVIRONMENT_DOC)
    sentence = text[/Rail names for =GUARDRAILS_RAILS=:(.*?)\.\s/m, 1]
    refute_nil sentence, "#{ENVIRONMENT_DOC} no longer carries a 'Rail names for =GUARDRAILS_RAILS=:' sentence"
    sentence.scan(/=([a-z_]+)=/).flatten.map(&:to_sym).uniq.sort
  end

  # Both collections are built from a glob and a regexp, so both can come back
  # empty and take every assertion below with them.
  def test_the_scan_found_something_to_compare
    refute_empty SOURCES, 'no library sources were found to scan'
    refute_empty code_variables, 'no environment variable was found in lib/ or exe/'
    refute_empty documented_variables, "no variable was found in #{ENVIRONMENT_DOC}"
  end

  def test_every_composed_variable_name_resolves
    unresolved = scan.last

    assert_empty unresolved,
                 "these reads compose a name this test cannot resolve, so teach it the constant " \
                 "rather than letting the comparison quietly narrow:\n  #{unresolved.join("\n  ")}"
  end

  def test_every_variable_the_library_reads_is_documented
    missing = code_variables - documented_variables

    assert_empty missing,
                 "these variables are read by lib/ or exe/ and named nowhere in the reference:\n  #{missing.join("\n  ")}"
  end

  def test_every_documented_variable_is_read
    unread = documented_variables - code_variables

    assert_empty unread,
                 "the reference names these and nothing reads them, so a reader who sets one gets " \
                 "nothing:\n  #{unread.join("\n  ")}"
  end

  def test_every_documented_rail_name_is_one_the_builder_accepts
    unknown = documented_rail_names - Vangrail::Builder::ALL_RAILS

    assert_empty unknown,
                 "the reference names these rails and GUARDRAILS_RAILS raises on them:\n  #{unknown.join(', ')}"
  end

  def test_every_rail_name_the_builder_accepts_is_documented
    undocumented = Vangrail::Builder::ALL_RAILS - documented_rail_names

    assert_empty undocumented,
                 "the builder accepts these and the reference does not name them:\n  #{undocumented.join(', ')}"
  end

  def test_the_pattern_list_names_reads_that_are_still_there
    stale = PATTERNS.reject do |(path, expression, _reason)|
      file = File.join(ROOT, path)
      File.file?(file) && File.read(file).include?(expression)
    end

    assert_empty stale, "the pattern list names reads that are gone:\n  #{stale.map(&:first).join("\n  ")}"
  end

  def test_the_reference_documents_the_generated_names
    assert File.read(ENVIRONMENT_DOC).include?(PATTERN_MARKER),
           "#{ENVIRONMENT_DOC} no longer carries \"#{PATTERN_MARKER}\", so the per-provider " \
           'overrides are undocumented. They are read for every provider name and can never ' \
           'appear in a table of names.'
  end

  # A rail nobody documented is a rail nobody can ask for on purpose. Read from
  # the directory rather than from a list here, so a new file is covered the day
  # it lands.
  def test_every_rail_class_appears_in_the_rail_reference
    doc = File.read(File.join(ROOT, 'docs', 'orgmode', 'reference', 'rails.org'))
    classes = Dir[File.join(ROOT, 'lib', 'vangrail', 'rails', '*.rb')].map do |path|
      File.basename(path, '.rb').split('_').map(&:capitalize).join
    end

    refute_empty classes, 'no rail classes were found to check'
    missing = classes.reject { |name| doc.include?("Rails::#{name}") }

    assert_empty missing, "these rails are in lib/vangrail/rails and not in the reference:\n  #{missing.join("\n  ")}"
  end

  def test_the_default_rail_set_the_reference_prints_is_the_one_the_builder_uses
    printed = File.read(ENVIRONMENT_DOC)[/The default set is\s+=([a-z,\s]+)=/m, 1]

    refute_nil printed, "#{ENVIRONMENT_DOC} no longer prints the default rail set"
    assert_equal Vangrail::Builder::DEFAULT_RAILS,
                 printed.gsub(/\s+/, '').split(',').map(&:to_sym),
                 'the reference prints a different default rail set than the builder uses'
  end
end
