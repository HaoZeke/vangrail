# frozen_string_literal: true

require 'rbconfig'
require_relative 'helper'
require_relative '../lib/vangrail/score_provider'

class TestScoreProvider < Minitest::Test
  def response_script
    <<~'RUBY'
      require 'json'
      request = JSON.parse($stdin.read)
      puts JSON.generate(
        schema: 'vangrail-score-response-v1',
        reader_id: request.fetch('reader_id'),
        model_id: request.fetch('model_id'),
        feature_schema: request.fetch('feature_schema'),
        side: request.fetch('side'),
        scores: { risk: request.fetch('text') == 'danger' ? 0.9 : 0.1 },
        cost: { calls: 1 },
        metadata: {
          argument: ARGV.fetch(0),
          origin: request.dig('context', 'origin'),
          inherited_secret: ENV['VANGRAIL_TEST_SECRET'],
        },
      )
    RUBY
  end

  def command_provider(command: [RbConfig.ruby, '-e', response_script, '; echo injected'], **options)
    Vangrail::ScoreProviders::Command.new(
      command: command,
      reader_id: 'encoder',
      model_id: 'encoder-v1',
      feature_schema: ['risk'],
      **options,
    )
  end

  def reader(provider)
    Vangrail::OptionalReader.new(
      id: 'encoder',
      model_id: 'encoder-v1',
      feature_schema: ['risk'],
      provider: provider,
    )
  end

  def test_command_provider_uses_json_over_stdin_without_a_shell_or_inherited_secrets
    ENV['VANGRAIL_TEST_SECRET'] = 'must-not-cross-process-boundary'

    result = reader(command_provider).score('danger', side: :context, origin: :tool)

    assert_predicate result, :valid?
    assert_equal 0.9, result.scores['risk']
    assert_equal '; echo injected', result.metadata['argument']
    assert_equal 'tool', result.metadata['origin']
    assert_nil result.metadata['inherited_secret']
  ensure
    ENV.delete('VANGRAIL_TEST_SECRET')
  end

  def test_command_failure_abstains_without_copying_stderr_into_the_result
    provider = command_provider(command: [RbConfig.ruby, '-e', "warn 'private model detail'; exit 7"])

    result = reader(provider).score('danger', side: :context)

    assert_predicate result, :abstained?
    assert_match(/status 7/, result.reason)
    refute_match(/private model detail/, result.reason)
  end

  def test_command_timeout_abstains
    provider = command_provider(
      command: [RbConfig.ruby, '-e', 'sleep 1'],
      timeout: 0.05,
    )

    result = reader(provider).score('danger', side: :context)

    assert_predicate result, :abstained?
    assert_match(/timed out/, result.reason)
  end

  def test_command_provider_bounds_input_and_output
    input_error = assert_raises(Vangrail::ProtocolError) do
      command_provider(max_input_bytes: 64).score('x' * 256, side: :context)
    end
    output_error = assert_raises(Vangrail::ProtocolError) do
      command_provider(
        command: [RbConfig.ruby, '-e', "$stdout.write('x' * 2048)"],
        max_output_bytes: 128,
      ).score('danger', side: :context)
    end

    assert_match(/request exceeds/, input_error.message)
    assert_match(/output exceeds/, output_error.message)
  end

  def test_endpoint_provider_uses_the_same_versioned_protocol
    http = Object.new
    http.define_singleton_method(:post_json) do |path, request|
      @path = path
      @request = request
      {
        'schema' => 'vangrail-score-response-v1',
        'reader_id' => request.fetch('reader_id'),
        'model_id' => request.fetch('model_id'),
        'feature_schema' => request.fetch('feature_schema'),
        'side' => request.fetch('side'),
        'scores' => { 'risk' => 0.75 },
      }
    end
    provider = Vangrail::ScoreProviders::Endpoint.new(
      http: http,
      path: '/score',
      reader_id: 'encoder',
      model_id: 'encoder-v1',
      feature_schema: ['risk'],
    )

    result = reader(provider).score('danger', side: :input, language: :en)

    assert_predicate result, :valid?
    assert_equal '/score', http.instance_variable_get(:@path)
    request = http.instance_variable_get(:@request)
    assert_equal 'vangrail-score-request-v1', request['schema']
    assert_equal 'en', request.dig('context', 'language')
  end

  def test_provider_rejects_an_unversioned_or_non_object_response
    missing_schema = command_provider(
      command: [RbConfig.ruby, '-e', "puts '{\"scores\":{}}'"],
    )
    non_object = command_provider(
      command: [RbConfig.ruby, '-e', "puts '[]'"],
    )

    first = reader(missing_schema).score('danger', side: :context)
    second = reader(non_object).score('danger', side: :context)

    assert_predicate first, :abstained?
    assert_match(/response schema/, first.reason)
    assert_predicate second, :abstained?
    assert_match(/JSON object/, second.reason)
  end

  def test_response_identity_is_validated_by_the_optional_reader
    wrong_identity = command_provider(
      command: [
        RbConfig.ruby,
        '-rjson',
        '-e',
        <<~'RUBY',
          request = JSON.parse($stdin.read)
          puts JSON.generate(
            schema: 'vangrail-score-response-v1',
            reader_id: 'different-reader',
            model_id: request.fetch('model_id'),
            feature_schema: request.fetch('feature_schema'),
            side: request.fetch('side'),
            scores: { risk: 0.5 },
          )
        RUBY
      ],
    )

    result = reader(wrong_identity).score('danger', side: :context)

    assert_predicate result, :invalid?
    assert_match(/reader identity/, result.reason)
  end
end
