# frozen_string_literal: true

require_relative 'helper'

# AgentDojo's two numbers on this runtime: the user tool may fire, the
# injected tool may not, even when the page is rewritten with the lexicon.
class TestDojo < Minitest::Test
  include GuardrailsTest

  def engine
    Vangrail::Engine.new(input: Vangrail::Builder.deterministic(:input),
                         context: Vangrail::Builder.deterministic(:context))
  end

  def tools
    Vangrail::Tools.new.tap do |set|
      set.register(:cite) { |args, _convo| Vangrail::Cell.text_of(args) }
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
    convo.screen([{ 'text' => page }])

    assert_predicate convo.invoke(:cite, arguments: page), :allowed?
    assert_predicate convo.invoke(:delete_all, arguments: page), :blocked?
    assert convo.invoked?(:cite)
    refute convo.invoked?(:delete_all)
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

  def test_config_hands_out_a_conversation_against_its_engine
    Dir.mktmpdir do |dir|
      File.write(File.join(dir, 'config.yml'), "models: []\nrails: {}\n")
      convo = Vangrail::Config.load(dir).conversation(prior: 1e-3, allow: allow)

      assert_instance_of Vangrail::Conversation, convo
      assert_instance_of Vangrail::Session, convo.session
    end
  end
end
