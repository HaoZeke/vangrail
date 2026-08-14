# frozen_string_literal: true

require 'minitest/autorun'
require 'tmpdir'
require_relative '../lib/nemo_guardrails'

# The config writer produces a folder `nemoguardrails server --config` can load.
class TestConfig < Minitest::Test
  def test_surf_default_names_a_main_and_two_self_check_models
    cfg = NemoGuardrails::Config.surf_default
    types = cfg.models.map { |m| m['type'] }
    assert_equal %w[main self_check_input self_check_output], types
    assert(cfg.models.all? { |m| m.dig('parameters', 'base_url') == NemoGuardrails::Willma.base_url })
  end

  def test_surf_default_enables_both_self_check_flows
    cfg = NemoGuardrails::Config.surf_default
    assert_equal ['self check input'], cfg.rails.dig('input', 'flows')
    assert_equal ['self check output'], cfg.rails.dig('output', 'flows')
  end

  # The server reads a Yes/No answer from the self-check tasks, so the JSON
  # contract the direct guard-model path uses has to be stripped out.
  def test_self_check_prompts_ask_a_yes_no_question_without_the_json_contract
    cfg = NemoGuardrails::Config.surf_default
    input = cfg.prompts.find { |p| p['task'] == 'self_check_input' }['content']
    assert_includes input, '{{ user_input }}'
    assert_includes input, 'Should the message be blocked (Yes or No)?'
    refute_includes input, '"violation"'
  end

  def test_self_check_output_prompt_uses_the_bot_response_variable
    cfg = NemoGuardrails::Config.surf_default
    output = cfg.prompts.find { |p| p['task'] == 'self_check_output' }['content']
    assert_includes output, '{{ bot_response }}'
    refute_includes output, '{{ user_input }}'
  end

  def test_write_produces_a_loadable_folder
    Dir.mktmpdir do |dir|
      cfg = NemoGuardrails::Config.surf_default(name: 'handbook')
      out = cfg.write!(dir)
      assert_equal File.join(dir, 'handbook'), out
      loaded = YAML.safe_load(File.read(File.join(out, 'config.yml')))
      assert_equal 'openai/gpt-oss-120b', loaded['models'].first['model']
      prompts = YAML.safe_load(File.read(File.join(out, 'prompts.yml')))
      assert_equal 2, prompts['prompts'].size
    end
  end

  def test_write_emits_colang_flow_files
    Dir.mktmpdir do |dir|
      cfg = NemoGuardrails::Config.new(
        name: 'flows',
        flows: { 'output' => "define flow block empty\n  bot inform answer unknown\n" }
      )
      out = cfg.write!(dir)
      colang = File.read(File.join(out, 'rails', 'output.co'))
      assert_includes colang, 'define flow block empty'
    end
  end

  def test_config_yaml_omits_empty_sections
    yaml = NemoGuardrails::Config.new(name: 'bare').config_yaml
    loaded = YAML.safe_load(yaml)
    assert_nil loaded['models']
    assert_nil loaded['rails']
  end
end
