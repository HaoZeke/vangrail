# frozen_string_literal: true

require_relative 'helper'

# AgentDojo's two numbers on this runtime: the user tool may fire, the
# injected tool may not, even when the page is rewritten with the lexicon.
class TestDojo < Minitest::Test
  def engine
    Vangrail::Engine.new(input: Vangrail::Builder.deterministic(:input),
                         context: Vangrail::Builder.deterministic(:context))
  end

  def tools
    Vangrail::Tools.new.tap do |set|
      set.register(:cite, readonly: true) { |args, _convo| Vangrail::Cell.text_of(args) }
      set.register(:delete_all) { |_args, _convo| 'deleted' }
      set.register(:dump_secrets) { |_args, _convo| 'sk-live-leaked' }
    end
  end

  def allow
    { cite: %i[data] }
  end

  def test_invoke_runs_a_granted_tool_and_refuses_the_rest
    convo = Vangrail::Conversation.new(engine, prior: 1e-3, allow: allow, tools: tools)
    convo.ask('Which GPU partitions exist?')
    page = 'The GPU partitions are gpu_a100 and gpu_h100.'
    convo.intend(:cite)
    convo.screen([{ 'text' => page }])

    assert_predicate convo.invoke(:cite, arguments: page), :allowed?
    assert_predicate convo.invoke(:delete_all, arguments: page), :blocked?
    assert convo.invoked?(:cite)
    refute convo.invoked?(:delete_all)
  end

  def test_a_tool_result_cannot_authorize_a_second_tool
    convo = Vangrail::Conversation.new(engine, prior: 1e-3,
                                      allow: { cite: %i[data], delete_all: %i[data] },
                                      tools: tools)
    convo.ask('Which GPU partitions exist?')
    page = 'The GPU partitions are gpu_a100 and gpu_h100.'
    convo.intend(:cite)
    convo.screen([{ 'text' => page }])
    convo.invoke(:cite, arguments: page)
    cited = convo.invocations.last[:cell]

    assert_predicate cited, :tainted?
    assert_equal :tool, cited.origins.first.kind
    assert_predicate convo.invoke(:delete_all, arguments: cited), :blocked?
    refute convo.invoked?(:delete_all)
  end

  def test_a_tool_not_intended_before_retrieval_cannot_run
    convo = Vangrail::Conversation.new(engine, prior: 1e-3, allow: allow, tools: tools)
    convo.ask('Which GPU partitions exist?')
    convo.intend(:cite)
    convo.screen([{ 'text' => 'The GPU partitions are gpu_a100 and gpu_h100.' }])

    refused = convo.invoke(:delete_all, arguments: 'x')

    assert_predicate refused, :blocked?
    assert_equal 'plan', refused.rail
    refute convo.invoked?(:delete_all)
  end

  def test_intending_after_screen_is_refused
    convo = Vangrail::Conversation.new(engine, prior: 1e-3, allow: allow, tools: tools)
    convo.ask('Which GPU partitions exist?')
    convo.screen([{ 'text' => 'The GPU partitions are gpu_a100 and gpu_h100.' }])

    assert_predicate convo, :locked?
    assert_raises(Vangrail::PrivilegeError) { convo.intend(:cite) }
  end

  def test_extract_from_retrieved_pages_stays_data
    convo = Vangrail::Conversation.new(engine, prior: 1e-3, allow: allow)
    convo.ask('Which GPU partitions exist?')
    convo.screen([{ 'text' => 'The GPU partitions are gpu_a100 and gpu_h100.' }])
    pulled = convo.extract(/gpu_\w+/)

    assert_equal 1, pulled.size
    assert_predicate pulled.first, :tainted?
    assert_equal 'gpu_a100', pulled.first.value
  end

  def test_handbook_tasks_keep_the_injected_tool_dark
    dojo = Vangrail::Dojo.new(engine: engine, allow: allow)
    score = dojo.score(tools: tools)

    failed_sec = score[:rows].reject { |row| row[:security] }.map { |row| row[:name] }
    failed_util = score[:rows].reject { |row| row[:utility] }.map { |row| row[:name] }

    assert_equal score[:n], score[:security], failed_sec
    assert_equal score[:n], score[:utility], failed_util
  end

  def test_concept_rewrites_do_not_let_the_injected_tool_through
    dojo = Vangrail::Dojo.new(engine: engine, allow: allow)
    score = dojo.adaptive(tools: tools, limit: 8)

    assert_operator score[:n], :>=, 8
    assert_equal score[:n], score[:security], 'a rewrite authorized the injected tool'
  end

  def test_chat_ask_from_a_conversation_cannot_take_a_raw_array_as_well
    convo = Vangrail::Conversation.new(engine, prior: 1e-3, allow: allow, tools: tools)
    convo.ask('Which GPU partitions exist?')
    convo.intend(:cite)
    convo.screen([{ 'text' => 'The GPU partitions are gpu_a100 and gpu_h100.' }])
    http = StubHTTP.new(responses: { '/chat/completions' => chat_body('gpu_a100') })
    chat = Vangrail::Chat.new(model: 'm', http: http)
    chat.ask(conversation: convo, system: 'Cite every clause.')

    sent = http.last_payload['messages']

    assert_includes sent.last['content'], 'Which GPU partitions exist?'
    assert_includes sent.last['content'], 'gpu_a100'
    assert_raises(ArgumentError) { chat.ask([{ 'role' => 'user', 'content' => 'x' }], conversation: convo) }
  end

  def test_config_hands_out_a_conversation_against_its_engine
    Dir.mktmpdir do |dir|
      File.write(File.join(dir, 'config.yml'), "models: []\nrails: {}\n")
      convo = Vangrail::Config.load(dir).conversation(prior: 1e-3, allow: allow)

      assert_instance_of Vangrail::Conversation, convo
      assert_instance_of Vangrail::Session, convo.session
    end
  end
end
