# frozen_string_literal: true

require_relative 'helper'

# The Colang subset: what parses, what is refused, and what a flow decides.
class TestColang < Minitest::Test
  include GuardrailsTest

  Parser = NemoGuardrails::Colang::Parser
  Interpreter = NemoGuardrails::Colang::Interpreter

  FLOW = <<~CO
    # a comment, ignored
    define flow self check input
      $allowed = execute self_check_input
      if not $allowed
        bot refuse to respond
        stop

    define bot refuse to respond
      "I'm sorry, I can't respond to that."
      "No."
  CO

  def test_a_flow_and_its_messages_parse
    program = Parser.parse(FLOW)
    assert_equal ['self check input'], program.flow_names
    assert_equal 2, program.bot_message('refuse to respond').size
    assert_equal 2, program.flow('self check input').body.size
  end

  def test_the_built_in_flows_parse_with_this_parser
    names = NemoGuardrails::Colang::Library.flow_names
    assert_includes names, 'self check input'
    assert_includes names, 'self check output'
    assert_includes names, 'self check facts'
  end

  def test_arguments_are_read_as_a_keyword_hash
    program = Parser.parse(<<~CO)
      define flow check
        $ok = execute my_action(threshold=3, label="high", flag=True)
    CO
    call = program.flow('check').body.first.expression
    assert_equal 'my_action', call.action
    assert_equal({ 'threshold' => 3, 'label' => 'high', 'flag' => true }, call.arguments)
  end

  def test_else_branches_parse
    program = Parser.parse(<<~CO)
      define flow check
        $ok = execute a
        if $ok
          bot yes
        else
          bot no

      define bot yes
        "yes"
      define bot no
        "no"
    CO
    node = program.flow('check').body.last
    assert_equal 1, node.then_body.size
    assert_equal 1, node.else_body.size
  end

  # A file using something outside the subset must fail at load. Skipping the
  # line would leave a configuration that claims a rail it does not run.
  def test_an_unsupported_statement_raises
    error = assert_raises(NemoGuardrails::ColangError) do
      Parser.parse("define flow x\n  user express greeting\n")
    end
    assert_includes error.message, 'unsupported statement'
  end

  def test_an_unsupported_definition_raises
    assert_raises(NemoGuardrails::ColangError) { Parser.parse("define wibble x\n  \"hi\"\n") }
  end

  def test_tabs_are_refused
    error = assert_raises(NemoGuardrails::ColangError) { Parser.parse("define flow x\n\t$a = execute b\n") }
    assert_includes error.message, 'tabs'
  end

  def test_the_error_names_the_file_and_line
    error = assert_raises(NemoGuardrails::ColangError) do
      Parser.parse("define flow x\n  $a = execute b\n  wibble\n", filename: 'rails/input.co')
    end
    assert_includes error.message, 'rails/input.co:3'
  end

  # --- interpreting ---

  def interpret(source, actions_hash, flow: 'self check input', context: {})
    program = Parser.parse(source)
    actions = NemoGuardrails::Actions.new(actions_hash)
    Interpreter.new(program: program, actions: actions).run(flow, context)
  end

  def test_a_refusing_flow_blocks_and_carries_the_message
    outcome = interpret(FLOW, { 'self_check_input' => ->(_a, _c) { false } })
    assert_equal :blocked, outcome.status
    assert_equal "I'm sorry, I can't respond to that.", outcome.content
  end

  # A refusal that varies between runs makes an incident report harder to read
  # for no benefit, so the first alternative is always the one used.
  def test_the_refusal_is_deterministic
    5.times do
      outcome = interpret(FLOW, { 'self_check_input' => ->(_a, _c) { false } })
      assert_equal "I'm sorry, I can't respond to that.", outcome.content
    end
  end

  def test_a_passing_flow_passes
    assert_equal :passed, interpret(FLOW, { 'self_check_input' => ->(_a, _c) { true } }).status
  end

  def test_an_action_sees_its_arguments_and_the_context
    seen = nil
    source = "define flow check\n  $ok = execute probe(level=2)\n"
    interpret(source, { 'probe' => lambda { |args, ctx|
      seen = [args, ctx]
      true
    } }, flow: 'check', context: { text: 'hello' })
    assert_equal({ 'level' => 2 }, seen[0])
    assert_equal 'hello', seen[1][:text]
  end

  # Assigning to the message variable is how a flow rewrites rather than
  # refuses, which is what makes :modified reachable from Colang.
  def test_assigning_to_the_message_variable_is_a_rewrite
    source = "define flow mask\n  $bot_message = execute redact\n"
    outcome = interpret(source, { 'redact' => ->(_a, _c) { 'masked answer' } }, flow: 'mask')
    assert_equal :modified, outcome.status
    assert_equal 'masked answer', outcome.content
  end

  def test_an_unknown_action_raises
    assert_raises(NemoGuardrails::UnknownAction) { interpret(FLOW, {}) }
  end

  def test_an_unknown_bot_message_raises
    source = "define flow x\n  bot never defined\n  stop\n"
    assert_raises(NemoGuardrails::UnknownAction) { interpret(source, {}, flow: 'x') }
  end

  def test_an_unknown_flow_raises
    assert_raises(NemoGuardrails::UnknownAction) { interpret(FLOW, {}, flow: 'no such flow') }
  end

  def test_comparison_conditions_evaluate
    source = <<~CO
      define flow check
        $level = execute level
        if $level == "high"
          bot warn
          stop

      define bot warn
        "too high"
    CO
    blocked = interpret(source, { 'level' => ->(_a, _c) { 'high' } }, flow: 'check')
    assert_equal :blocked, blocked.status
    passed = interpret(source, { 'level' => ->(_a, _c) { 'low' } }, flow: 'check')
    assert_equal :passed, passed.status
  end

  # --- as a rail ---

  def test_a_flow_used_as_a_rail_returns_a_blocked_result
    program = NemoGuardrails::Colang::Library.program.merge(Parser.parse(FLOW))
    actions = NemoGuardrails::Actions.new('self_check_input' => ->(_a, ctx) { !ctx[:text].include?('bad') })
    rail = NemoGuardrails::Rails::ColangFlow.new(
      flow_name: 'self check input', program: program, actions: actions, sides: [:input]
    )
    engine = NemoGuardrails::Engine.new(input: [rail])
    blocked = engine.check_input('something bad')
    assert blocked.blocked?
    assert_equal "I'm sorry, I can't respond to that.", blocked.content
    assert engine.check_input('something fine').passed?
  end

  # A flow can call anything registered, so this class cannot know what its
  # decision depends on and must not let the engine memoize it.
  def test_a_colang_rail_is_not_memoizable
    rail = NemoGuardrails::Rails::ColangFlow.new(
      flow_name: 'self check input', program: NemoGuardrails::Colang::Library.program,
      actions: NemoGuardrails::Actions.new
    )
    assert_nil rail.cache_key('text', side: :input)
  end
end
