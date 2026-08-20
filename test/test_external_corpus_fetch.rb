# frozen_string_literal: true

require 'digest'
require 'json'
require 'stringio'
require_relative 'helper'
require_relative '../script/fetch_external'

class TestExternalCorpusFetch < Minitest::Test
  COMMITS = {
    'bipia' => 'a004b69ec0dd446e0afd461d98cb5e96e120a5d0',
    'jailbreak_llms' => '4f4031bf8be187f4478c7f94f42b08714722c12e',
  }.freeze
  FILES = {
    'bipia_text_attack_test.json' =>
      ['bipia', 6_322, '75750e7b4e8b34e8f9d88d89b357aeaaf02bd07f9e493ccd37eda74a0cd7c7f8'],
    'bipia_code_attack_test.json' =>
      ['bipia', 16_356, '892545c5aaec0645b1ded65dc7816b3d70e9ef4eadcba2301a7a3db93676b6e0'],
    'jailbreak_prompts_2023_12_25.csv' =>
      ['jailbreak_llms', 3_778_717, 'accf97463de96c33c48453dfee9600191ff6fd5a0c43f3f11d5ebf98d1a5de55'],
    'regular_prompts_2023_12_25.csv' =>
      ['jailbreak_llms', 24_307_583, 'fb82e3f88fbd5d9c6edf8927b138510f339b85012cab24d41d13e1665a9c5819'],
  }.freeze

  def test_manifest_pins_every_external_payload_to_a_revision_and_digest
    manifest = JSON.parse(File.read(File.expand_path('../evaluation/benchmark_sources.json', __dir__)))
    external = manifest.fetch('external_corpora')

    assert_equal COMMITS, external.fetch('repositories').transform_values { |row| row.fetch('source_commit') }
    assert_equal FILES.keys.sort, external.fetch('files').keys.sort

    FILES.each do |name, (corpus, bytes, sha256)|
      row = external.fetch('files').fetch(name)
      commit = COMMITS.fetch(corpus)

      assert_equal corpus, row.fetch('corpus')
      assert_equal bytes, row.fetch('bytes')
      assert_equal sha256, row.fetch('sha256')
      assert_match(%r{/#{commit}/}, row.fetch('url'))
      refute_match(%r{/(main|master)/}, row.fetch('url'))
    end
  end

  def test_valid_cached_payload_is_reused_without_network_access
    payload = 'published corpus'

    Dir.mktmpdir do |dir|
      File.binwrite(File.join(dir, 'corpus.json'), payload)
      download = lambda { |_url| flunk 'valid cache must not be downloaded' }

      fetcher(dir, payload, download: download).fetch_all

      assert_equal payload, File.binread(File.join(dir, 'corpus.json'))
    end
  end

  def test_corrupt_cache_is_replaced_only_after_the_download_is_verified
    payload = 'published corpus'
    calls = []
    download = lambda do |url|
      calls << url
      payload
    end

    Dir.mktmpdir do |dir|
      path = File.join(dir, 'corpus.json')
      File.binwrite(path, 'corrupt cache')

      fetcher(dir, payload, download: download).fetch_all

      assert_equal ['https://example.invalid/corpus.json'], calls
      assert_equal payload, File.binread(path)
      assert_empty Dir[File.join(dir, '.*.tmp*')]
    end
  end

  def test_bad_download_never_overwrites_the_cached_payload
    payload = 'published corpus'

    Dir.mktmpdir do |dir|
      path = File.join(dir, 'corpus.json')
      File.binwrite(path, 'corrupt cache')
      runner = fetcher(dir, payload, download: ->(_url) { 'truncated response' })

      error = assert_raises(ExternalCorpusFetch::IntegrityError) { runner.fetch_all }

      assert_match(/corpus\.json/, error.message)
      assert_equal 'corrupt cache', File.binread(path)
      assert_empty Dir[File.join(dir, '.*.tmp*')]
    end
  end

  private

  def fetcher(destination, payload, download:)
    ExternalCorpusFetch::Fetcher.new(
      destination: destination,
      sources: {
        'corpus.json' => {
          'url' => 'https://example.invalid/corpus.json',
          'bytes' => payload.bytesize,
          'sha256' => Digest::SHA256.hexdigest(payload),
        },
      },
      download: download,
      output: StringIO.new,
    )
  end
end
