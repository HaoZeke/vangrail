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

  # Only vendor-neutral entries are built in. A hostname compiled into the gem
  # is an endpoint every installation inherits whether it can reach it or not.
  def test_only_the_local_provider_is_built_in
    assert_equal %w[llmlite], Vangrail::Provider.names
  end

  # Local first. A loopback endpoint costs nothing per call and needs no
  # shared credential, so an application with one running should use it untold.
  def test_a_registered_gateway_comes_after_the_local_provider
    Vangrail::Providers.register_gateway(
      Vangrail::Providers::Gateway::Spec.new(
        name: 'hub', base_url: 'https://gateway.invalid/api/v0',
        models: { judge: 'some/instruct' }, key_env: 'HUB_KEY'
      ),
    )

    assert_equal %w[llmlite hub], Vangrail::Provider.names
  ensure
    Vangrail::Providers.reset!
  end

  def test_register_gateway_still_accepts_the_keyword_form
    Vangrail::Providers.register_gateway(
      name: 'hub', base_url: 'https://gateway.invalid/api/v0',
      models: { judge: 'some/instruct' }, key_env: 'HUB_KEY'
    )

    assert_equal %w[llmlite hub], Vangrail::Provider.names
    assert_equal 'some/instruct', Vangrail::Provider['hub'].model(:judge)
  ensure
    Vangrail::Providers.reset!
  end

  def test_registering_a_name_twice_replaces_it
    2.times do
      Vangrail::Providers.register_gateway(
        Vangrail::Providers::Gateway::Spec.new(
          name: 'hub', base_url: 'https://gateway.invalid/api/v0', key_env: 'HUB_KEY',
        ),
      )
    end

    assert_equal 1, Vangrail::Provider.names.count('hub')
  ensure
    Vangrail::Providers.reset!
  end

  # A deployment should not need code to name its own endpoint.
  def test_a_gateway_can_be_described_entirely_by_environment
    env = {
      'GUARDRAILS_GATEWAY_NAME' => 'hub',
      'GUARDRAILS_GATEWAY_API_BASE' => 'https://gateway.invalid/api/v0',
      'GUARDRAILS_GATEWAY_API_KEY' => 'tok',
      'GUARDRAILS_GATEWAY_JUDGE_MODEL' => 'some/instruct',
      'GUARDRAILS_GATEWAY_GUARD_MODEL' => 'some/guard',
      'GUARDRAILS_GATEWAY_GUARD_PRESET' => 'apriel_guard',
    }
    Vangrail::Providers.install!(env)
    hub = Vangrail::Provider['hub']

    refute_nil hub
    assert_equal 'https://gateway.invalid/api/v0', hub.base_url
    assert_equal 'some/instruct', hub.model(:judge)
    assert_predicate hub, :guard?
    assert_equal :apriel_guard, hub.guard_preset
  ensure
    Vangrail::Providers.reset!
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
      refute_predicate chosen, :available?
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
      'GUARDRAILS_JUDGE_MODEL' => 'some-model',
    )

    assert_equal 'env', chosen.name
    assert_equal 'some-model', chosen.model(:judge)
    assert_predicate chosen, :available?
  end

  def test_model_overrides_reach_a_registered_provider
    chosen = Vangrail::Provider.resolve(
      'GUARDRAILS_PROVIDER' => 'llmlite',
      'GUARDRAILS_JUDGE_MODEL' => 'my/judge',
    )

    assert_equal 'my/judge', chosen.model(:judge)
  end

  # The difference that changes which rail class gets built.
  def test_llmlite_offers_no_classifier
    llmlite = Vangrail::Provider['llmlite']

    assert_nil llmlite.model(:guard)
    refute_predicate llmlite, :guard?
    assert llmlite.local
  end

  def test_a_gateway_with_a_classifier_reports_one
    Vangrail::Providers.register_gateway(
      Vangrail::Providers::Gateway::Spec.new(
        name: 'hub', base_url: 'https://gateway.invalid/api/v0',
        models: { judge: 'some/instruct', guard: 'some/guard' },
        guard_preset: :apriel_guard, key_env: 'HUB_KEY'
      ),
      env: { 'HUB_KEY' => 'tok' },
    )
    hub = Vangrail::Provider['hub']

    assert_predicate hub, :guard?
    assert_equal :apriel_guard, hub.guard_preset
    refute hub.local
  ensure
    Vangrail::Providers.reset!
  end

  def test_chat_raises_for_a_role_the_provider_cannot_serve
    llmlite = Vangrail::Provider['llmlite']
    assert_raises(Vangrail::ConfigError) { llmlite.chat(:guard) }
  end
end

class TestProvider < Minitest::Test
  def test_llmlite_names_no_model_until_the_environment_does
    llmlite = Vangrail::Provider['llmlite']

    assert_nil llmlite.model(:judge)
    assert_raises(Vangrail::ConfigError) { llmlite.chat(:judge) }
  end

  def test_chat_for_a_served_role_points_at_the_provider
    env = { 'LLMLITE_MODEL' => 'named-model' }
    Vangrail::Providers.install!(env)
    chat = Vangrail::Provider['llmlite'].chat(:judge)

    assert_equal Vangrail::Providers::Llmlite.base_url(env), chat.http.base_url
    assert_equal 'named-model', chat.model
  end

  def test_to_h_does_not_probe
    probed = 0
    named = Vangrail::Provider.new(
      name: 'hub', base_url: 'http://hub.invalid/v1',
      key_resolver: -> { 'k' },
      probe: lambda {
        probed += 1
        true
      }
    )

    refute_includes named.to_h.keys, 'available'
    assert_equal 0, probed
  end

  # --- llmlite specifics ---

  def test_llmlite_reads_its_port_from_either_name
    assert_equal 9999, Vangrail::Providers::Llmlite.port('LLMLITE_PORT' => '9999')
    assert_equal 8888, Vangrail::Providers::Llmlite.port('GROK_SHIM_PORT' => '8888')
    assert_equal 8760, Vangrail::Providers::Llmlite.port({})
  end

  def test_isolate_env_forgets_the_llmlite_aliases
    snapshot = @saved_env
    ENV['GROK_SHIM_PORT'] = '9999'
    ENV['GROK_LLMLITE_MODEL'] = 'not-the-default'
    isolate_env!

    refute ENV.key?('GROK_SHIM_PORT')
    refute ENV.key?('GROK_LLMLITE_MODEL')
    assert_equal 8760, Vangrail::Providers::Llmlite.port
    assert_nil Vangrail::Providers::Llmlite.model
  ensure
    ENV.delete('GROK_SHIM_PORT')
    ENV.delete('GROK_LLMLITE_MODEL')
    @saved_env = snapshot
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

  # Most explicit first: the environment variable, then a key file, then pass.
  def spec(key_file: nil, pass_entry: nil)
    Vangrail::Providers::Gateway::Spec.new(
      name: 'hub', base_url: 'https://gateway.invalid/api/v0', models: {},
      key_env: 'HUB_KEY', key_file: key_file, pass_entry: pass_entry
    )
  end

  def test_the_gateway_token_comes_from_the_environment_first
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'api_key')
      File.write(path, "from-file\n")
      env = { 'HUB_KEY' => 'from-env' }

      assert_equal 'from-env', Vangrail::Providers::Gateway.token(spec(key_file: path), env)
    end
  end

  def test_the_gateway_token_falls_back_to_a_key_file
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'api_key')
      File.write(path, "  file-token  \n")

      assert_equal 'file-token',
                   Vangrail::Providers::Gateway.token(spec(key_file: path, pass_entry: 'absent/entry'), {})
    end
  end

  def test_a_key_file_can_be_pointed_somewhere_else_by_environment
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'elsewhere')
      File.write(path, "redirected\n")
      env = { 'HUB_KEY_FILE' => path }

      assert_equal 'redirected', Vangrail::Providers::Gateway.token(spec(key_file: '/nowhere'), env)
    end
  end

  def test_no_source_resolving_is_no_token
    assert_nil Vangrail::Providers::Gateway.token(spec(key_file: '/nowhere'), {})
  end
end
