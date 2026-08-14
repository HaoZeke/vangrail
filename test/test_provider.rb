# frozen_string_literal: true

require_relative 'helper'

# Which endpoint answers, and what it is allowed to be asked for.
class TestProvider < Minitest::Test
  include GuardrailsTest

  def setup
    isolate_env!
    Vangrail::Providers.install!
  end

  def teardown
    restore_env!
    Vangrail::Providers.install!
  end

  def provider(name:, available:, **kwargs)
    Vangrail::Provider.new(
      name: name, base_url: "http://#{name}.invalid/v1",
      key_resolver: -> { 'key' }, probe: -> { available }, **kwargs
    )
  end

  def with_registry(*providers)
    Vangrail::Provider.registry.clear
    providers.each { |p| Vangrail::Provider.register(p) }
    yield
  ensure
    Vangrail::Providers.install!
  end

  # Local first. A loopback endpoint costs nothing per call and needs no shared
  # credential, so an application with one running should use it untold.
  def test_registration_order_decides_and_local_is_registered_first
    assert_equal %w[llmlite willma], Vangrail::Provider.names
  end

  def test_resolve_takes_the_first_available_provider
    with_registry(provider(name: 'down', available: false), provider(name: 'up', available: true)) do
      assert_equal 'up', Vangrail::Provider.resolve({}).name
    end
  end

  def test_resolve_is_nil_when_nothing_is_available
    with_registry(provider(name: 'down', available: false)) do
      assert_nil Vangrail::Provider.resolve({})
    end
  end

  # A pinned provider that is down must not silently fall through to another
  # one: the operator named an endpoint and deserves to see it fail.
  def test_a_pinned_provider_is_taken_even_when_it_is_down
    with_registry(provider(name: 'down', available: false), provider(name: 'up', available: true)) do
      chosen = Vangrail::Provider.resolve('GUARDRAILS_PROVIDER' => 'down')
      assert_equal 'down', chosen.name
      refute chosen.available?
    end
  end

  def test_an_unknown_pinned_provider_raises_rather_than_falling_back
    error = assert_raises(Vangrail::ConfigError) do
      Vangrail::Provider.resolve('GUARDRAILS_PROVIDER' => 'nowhere')
    end
    assert_includes error.message, 'llmlite'
  end

  def test_an_explicit_base_url_beats_the_registry
    chosen = Vangrail::Provider.resolve(
      'GUARDRAILS_API_BASE' => 'http://elsewhere.invalid/v1',
      'GUARDRAILS_API_KEY' => 'k',
      'GUARDRAILS_JUDGE_MODEL' => 'some-model'
    )
    assert_equal 'env', chosen.name
    assert_equal 'some-model', chosen.model(:judge)
    assert chosen.available?
  end

  def test_model_overrides_reach_a_registered_provider
    chosen = Vangrail::Provider.resolve(
      'GUARDRAILS_PROVIDER' => 'willma',
      'WILLMA_API_KEY' => 'tok',
      'GUARDRAILS_JUDGE_MODEL' => 'my/judge'
    )
    assert_equal 'my/judge', chosen.model(:judge)
  end

  # The difference that changes which rail class gets built.
  def test_llmlite_offers_no_classifier
    llmlite = Vangrail::Provider['llmlite']
    assert_nil llmlite.model(:guard)
    refute llmlite.guard?
    assert llmlite.local
  end

  def test_a_gateway_with_a_classifier_reports_one
    ENV['WILLMA_API_KEY'] = 'tok'
    Vangrail::Providers.install!
    willma = Vangrail::Provider['willma']
    assert willma.guard?
    assert_equal :apriel_guard, willma.guard_preset
    refute willma.local
  end

  def test_chat_raises_for_a_role_the_provider_cannot_serve
    llmlite = Vangrail::Provider['llmlite']
    assert_raises(Vangrail::ConfigError) { llmlite.chat(:guard) }
  end

  def test_chat_for_a_served_role_points_at_the_provider
    chat = Vangrail::Provider['llmlite'].chat(:judge)
    assert_equal Vangrail::Providers::Llmlite.base_url, chat.http.base_url
    assert_equal Vangrail::Providers::Llmlite::DEFAULT_MODEL, chat.model
  end

  # --- llmlite specifics ---

  def test_llmlite_reads_its_port_from_either_name
    assert_equal 9999, Vangrail::Providers::Llmlite.port('LLMLITE_PORT' => '9999')
    assert_equal 8888, Vangrail::Providers::Llmlite.port('GROK_SHIM_PORT' => '8888')
    assert_equal 8760, Vangrail::Providers::Llmlite.port({})
  end

  def test_llmlite_probe_is_false_for_a_closed_port
    probe = TCPServer.new('127.0.0.1', 0)
    port = probe.addr[1]
    probe.close
    refute Vangrail::Providers::Llmlite.listening?('LLMLITE_PORT' => port.to_s)
  end

  def test_llmlite_probe_is_true_for_an_open_port
    server = TCPServer.new('127.0.0.1', 0)
    port = server.addr[1]
    assert Vangrail::Providers::Llmlite.listening?('LLMLITE_PORT' => port.to_s)
  ensure
    server&.close
  end

  # --- gateway token resolution ---

  def test_the_gateway_token_comes_from_the_environment_first
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'api_key')
      File.write(path, "from-file\n")
      env = { 'WILLMA_API_KEY_FILE' => path, 'WILLMA_API_KEY' => 'from-env' }
      Vangrail::Providers::Willma.reset!
      assert_equal 'from-env', Vangrail::Providers::Willma.token(env)
    end
  ensure
    Vangrail::Providers::Willma.reset!
  end

  def test_the_gateway_token_falls_back_to_a_key_file
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'api_key')
      File.write(path, "  file-token  \n")
      Vangrail::Providers::Willma.reset!
      env = { 'WILLMA_API_KEY_FILE' => path, 'WILLMA_PASS_ENTRY' => 'absent/entry' }
      assert_equal 'file-token', Vangrail::Providers::Willma.token(env)
    end
  ensure
    Vangrail::Providers::Willma.reset!
  end
end
