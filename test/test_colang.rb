# frozen_string_literal: true

require_relative 'helper'

# The Colang subset: what parses, what is refused, and what a flow decides.
class TestColang < Minitest::Test
  Parser = Vangrail::Colang::Parser
  Interpreter = Vangrail::Colang::Interpreter

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
    names = Vangrail::Colang::Library.flow_names

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
    assert_equal 3, call.arguments['threshold'].value
    assert_equal 'high', call.arguments['label'].value
    assert_equal true, call.arguments['flag'].value
  end

  # One value grammar: the same literal is a value in assign, if, and arguments.
  def test_a_value_is_the_same_in_assign_if_and_arguments
    program = Parser.parse(<<~CO)
      define flow check
        $n = 1
        $ok = execute probe(n=1)
        if $n == 1
          stop
    CO
    body = program.flow('check').body
    assigned = body[0].expression
    argument = body[1].expression.arguments['n']
    compared = body[2].condition.right

    assert_equal 1, assigned.value
    assert_equal assigned, argument
    assert_equal assigned, compared
  end

  def test_equality_inside_quotes_is_not_a_compare
    program = Parser.parse(<<~CO)
      define flow check
        if "a == b" == $x
          stop
    CO
    node = program.flow('check').body.first.condition

    assert_instance_of Vangrail::Colang::Compare, node
    assert_equal 'a == b', node.left.value
    assert_equal '==', node.operator
    assert_equal 'x', node.right.name
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
    error = assert_raises(Vangrail::ColangError) do
      Parser.parse("define flow x\n  user express greeting\n")
    end
    assert_includes error.message, 'unsupported statement'
  end

  def test_an_unsupported_definition_raises
    assert_raises(Vangrail::ColangError) { Parser.parse("define wibble x\n  \"hi\"\n") }
  end

  def test_tabs_are_refused
    error = assert_raises(Vangrail::ColangError) { Parser.parse("define flow x\n\t$a = execute b\n") }
    assert_includes error.message, 'tabs'
    nested = assert_raises(Vangrail::ColangError) { Parser.parse("define flow x\n  \t$a = execute b\n") }
    assert_includes nested.message, 'tabs'
  end

  def test_the_error_names_the_file_and_line
    error = assert_raises(Vangrail::ColangError) do
      Parser.parse("define flow x\n  $a = execute b\n  wibble\n", filename: 'rails/input.co')
    end
    assert_includes error.message, 'rails/input.co:3'
  end

  # --- interpreting ---

  def interpret(source, actions_hash, flow: 'self check input', context: {})
    program = Parser.parse(source)
    actions = Vangrail::Actions.new(actions_hash)
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
    assert_raises(Vangrail::UnknownAction) { interpret(FLOW, {}) }
  end

  # A missing bot in an unreached branch must still fail at load, not on
  # the first turn that happens to take that branch.
  def test_a_missing_bot_is_an_error_at_load
    source = <<~CO
      define flow x
        if False
          bot never defined
          stop
    CO
    program = Parser.parse(source)
    error = assert_raises(Vangrail::ColangError) do
      Interpreter.new(program: program, actions: Vangrail::Actions.new)
    end
    refute_instance_of Vangrail::UnknownAction, error
    assert_includes error.message, 'never defined'
  end

  def test_an_unknown_flow_raises_at_load
    program = Parser.parse(FLOW)
    error = assert_raises(Vangrail::ColangError) do
      Vangrail::Rails::ColangFlow.new(
        flow_name: 'no such flow', program: program, actions: Vangrail::Actions.new,
      )
    end
    refute_instance_of Vangrail::UnknownAction, error
    assert_includes error.message, 'no such flow'
  end

  def test_an_unknown_flow_raises_when_run_directly
    error = assert_raises(Vangrail::ColangError) { interpret(FLOW, {}, flow: 'no such flow') }
    refute_instance_of Vangrail::UnknownAction, error
  end

  def test_stop_does_not_raise_a_control_exception
    refute_includes Interpreter.constants, :Stopped
    outcome = interpret(FLOW, { 'self_check_input' => ->(_a, _c) { false } })

    assert_equal :blocked, outcome.status
  end

  def test_the_turn_text_is_bound_as_user_message
    seen = nil
    source = "define flow check\n  $ok = execute probe(msg=$user_message)\n"
    interpret(source, { 'probe' => lambda { |args, _ctx|
      seen = args['msg']
    } }, flow: 'check', context: { text: 'hello' })

    assert_equal 'hello', seen
  end

  # Input and context seed the user pair; output seeds the bot pair. Seeding
  # both pairs from the same text would make an output flow that reads
  # $user_message judge the answer.
  def test_input_seeds_the_user_bindings
    seen = nil
    source = <<~CO
      define flow check
        $ok = execute probe(user=$user_message, alias=$user_input, bot=$bot_message)
    CO
    interpret(source, { 'probe' => ->(args, _) { seen = args } }, flow: 'check',
                                                                 context: { text: 'hello', side: :input })

    assert_equal 'hello', seen['user']
    assert_equal 'hello', seen['alias']
    assert_nil seen['bot']
  end

  def test_context_seeds_the_user_bindings
    seen = nil
    source = <<~CO
      define flow check
        $ok = execute probe(user=$user_message, alias=$user_input, bot=$bot_message)
    CO
    interpret(source, { 'probe' => ->(args, _) { seen = args } }, flow: 'check',
                                                                 context: { text: 'a page', side: :context })

    assert_equal 'a page', seen['user']
    assert_equal 'a page', seen['alias']
    assert_nil seen['bot']
  end

  def test_output_seeds_the_bot_bindings
    seen = nil
    source = <<~CO
      define flow check
        $ok = execute probe(bot=$bot_message, alias=$bot_response, user=$user_message)
    CO
    interpret(source, { 'probe' => ->(args, _) { seen = args } }, flow: 'check',
                                                                 context: { text: 'the answer', side: :output })

    assert_equal 'the answer', seen['bot']
    assert_equal 'the answer', seen['alias']
    assert_nil seen['user']
  end

  def test_an_output_rail_does_not_bind_user_message_to_the_answer
    seen = nil
    source = <<~CO
      define flow check
        $ok = execute probe(user=$user_message, bot=$bot_message)
    CO
    program = Parser.parse(source)
    actions = Vangrail::Actions.new('probe' => lambda { |args, _|
      seen = args
      true
    })
    rail = Vangrail::Rails::ColangFlow.new(
      flow_name: 'check', program: program, actions: actions, sides: [:output],
    )
    Vangrail::Engine.new(output: [rail]).check_output('the answer', user_input: 'the question')

    assert_nil seen['user']
    assert_equal 'the answer', seen['bot']
  end

  # $user_input and $bot_response are rewrite aliases of the message bindings.
  def test_assigning_user_input_is_a_rewrite
    source = "define flow mask\n  $user_input = execute redact\n"
    outcome = interpret(source, { 'redact' => ->(_a, _c) { 'other' } }, flow: 'mask',
                                                                        context: { text: 'hello', side: :input })

    assert_equal :modified, outcome.status
    assert_equal 'other', outcome.content
  end

  def test_assigning_bot_response_is_a_rewrite
    source = "define flow mask\n  $bot_response = execute redact\n"
    outcome = interpret(source, { 'redact' => ->(_a, _c) { 'masked answer' } }, flow: 'mask',
                                                                               context: { side: :output })

    assert_equal :modified, outcome.status
    assert_equal 'masked answer', outcome.content
  end

  # Rewrite is a change to a content binding, not a scan of whatever names a
  # flow happened to assign.
  def test_assigning_another_name_is_not_a_rewrite
    source = "define flow mask\n  $scratch = execute redact\n"
    outcome = interpret(source, { 'redact' => ->(_a, _c) { 'other' } }, flow: 'mask',
                                                                        context: { text: 'hello' })

    assert_equal :passed, outcome.status
  end

  def test_a_bot_from_another_file_is_visible_after_merge
    source = <<~CO
      define flow x
        bot refuse to respond
        stop
    CO
    program = Vangrail::Colang::Library.program.merge(Parser.parse(source))
    outcome = Interpreter.new(program: program, actions: Vangrail::Actions.new).run('x', {})

    assert_equal :blocked, outcome.status
    assert_equal "I'm sorry, I can't respond to that.", outcome.content
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

  def test_an_integer_assignment_is_a_value
    source = <<~CO
      define flow check
        $n = 1
        if $n == 1
          bot warn
          stop

      define bot warn
        "n"
    CO
    outcome = interpret(source, {}, flow: 'check')

    assert_equal :blocked, outcome.status
    assert_equal 'n', outcome.content
  end

  def test_execute_is_a_condition_value
    source = <<~CO
      define flow check
        if execute allowed
          bot warn
          stop

      define bot warn
        "no"
    CO
    blocked = interpret(source, { 'allowed' => ->(_a, _c) { true } }, flow: 'check')

    assert_equal :blocked, blocked.status
    passed = interpret(source, { 'allowed' => ->(_a, _c) { false } }, flow: 'check')

    assert_equal :passed, passed.status
  end

  def test_a_quoted_equality_evaluates_as_a_literal
    source = <<~CO
      define flow check
        $x = execute val
        if "a == b" == $x
          bot warn
          stop

      define bot warn
        "hit"
    CO
    blocked = interpret(source, { 'val' => ->(_a, _c) { 'a == b' } }, flow: 'check')

    assert_equal :blocked, blocked.status
    passed = interpret(source, { 'val' => ->(_a, _c) { 'other' } }, flow: 'check')

    assert_equal :passed, passed.status
  end

  # --- as a rail ---

  def test_a_flow_used_as_a_rail_returns_a_blocked_result
    program = Vangrail::Colang::Library.program.merge(Parser.parse(FLOW))
    actions = Vangrail::Actions.new('self_check_input' => ->(_a, ctx) { !ctx[:text].include?('bad') })
    rail = Vangrail::Rails::ColangFlow.new(
      flow_name: 'self check input', program: program, actions: actions, sides: [:input],
    )
    engine = Vangrail::Engine.new(input: [rail])
    blocked = engine.check_input('something bad')

    assert_predicate blocked, :blocked?
    assert_equal "I'm sorry, I can't respond to that.", blocked.content
    assert_predicate engine.check_input('something fine'), :passed?
  end

  # A flow can call anything registered, so this class cannot know what its
  # decision depends on and must not let the engine memoize it.
  def test_a_colang_rail_is_not_memoizable
    rail = Vangrail::Rails::ColangFlow.new(
      flow_name: 'self check input', program: Vangrail::Colang::Library.program,
      actions: Vangrail::Actions.new
    )

    assert_nil rail.cache_key('text', side: :input)
  end

  # Those actions include model calls. Inheriting the default offline? would
  # report a config-folder engine as free when every check is a round trip.
  def test_a_colang_rail_is_not_offline
    rail = Vangrail::Rails::ColangFlow.new(
      flow_name: 'self check input', program: Vangrail::Colang::Library.program,
      actions: Vangrail::Actions.new
    )

    refute_predicate rail, :offline?
  end
end
