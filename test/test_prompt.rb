# frozen_string_literal: true

require_relative 'helper'

# The template slice, which exists to be small: the text it substitutes is
# attacker-influenced by construction.
class TestPrompt < Minitest::Test
  include GuardrailsTest

  P = Vangrail::Prompt

  def test_variables_substitute
    assert_equal 'hello world', P.render('hello {{ name }}', 'name' => 'world')
  end

  def test_an_unknown_variable_renders_empty
    assert_equal 'hello ', P.render('hello {{ nobody }}', {})
  end

  def test_filters_apply
    assert_equal 'LOUD', P.render('{{ x | upper }}', 'x' => 'loud')
    assert_equal 'quiet', P.render('{{ x | lower }}', 'x' => 'QUIET')
    assert_equal 'trimmed', P.render('{{ x | trim }}', 'x' => '  trimmed  ')
  end

  def test_conditionals_include_and_exclude
    template = 'a{% if x %} b{% endif %} c'

    assert_equal 'a b c', P.render(template, 'x' => 'yes')
    assert_equal 'a c', P.render(template, 'x' => '')
    assert_equal 'a c', P.render(template, {})
  end

  def test_nested_conditionals_resolve
    template = '{% if a %}A{% if b %}B{% endif %}{% endif %}'

    assert_equal 'AB', P.render(template, 'a' => 1, 'b' => 1)
    assert_equal 'A', P.render(template, 'a' => 1)
  end

  def test_dotted_lookup_reads_nested_values
    assert_equal 'deep', P.render('{{ a.b }}', 'a' => { 'b' => 'deep' })
  end

  def test_false_zero_and_empty_are_not_treated_as_missing
    assert_equal '0', P.render('{{ n }}', 'n' => 0)
    assert_equal 'false', P.render('{{ n }}', 'n' => false)
    assert_equal '', P.render('{{ n }}', 'n' => '')
    assert_equal '0', P.render('{{ n }}', n: 0)
    assert_equal '0', P.render('{{ a.b }}', 'a' => { 'b' => 0 })
    assert_equal 'false', P.render('{{ a.b }}', 'a' => { 'b' => false })
    assert_equal 'yes', P.render('{% if n %}yes{% endif %}', 'n' => 0)
    assert_equal '', P.render('{% if n %}yes{% endif %}', 'n' => false)
  end

  # A prompt that silently drops the rule someone wrote is worse than one that
  # refuses to load.
  def test_an_unknown_filter_raises
    assert_raises(ArgumentError) { P.render('{{ x | shout }}', 'x' => 'hi') }
  end

  def test_an_unsupported_tag_raises
    assert_raises(ArgumentError) { P.render('{% for x in y %}{% endfor %}', {}) }
  end

  # Substituted text is data. Whatever it contains stays inert.
  def test_substituted_text_is_never_evaluated
    payload = '{{ other }} {% if other %}injected{% endif %}'
    rendered = P.render('user said: {{ text }}', 'text' => payload, 'other' => 'secret')

    assert_equal "user said: #{payload}", rendered
  end
end
