# frozen_string_literal: true

# Downloads the published corpora the external evaluation runs against.
#
#   ruby script/fetch_external.rb [directory]
#
# Nothing here is checked in. These are other people's datasets under their own
# licences and terms, they are large, and one of them is a collection of
# in-the-wild jailbreak prompts whose contents are exactly what you would
# expect; a guardrail gem is not the right place to redistribute any of it. The
# scripts fetch, measure, and check in the counts.
#
#   BIPIA           Yi et al., indirect prompt injection benchmark. The attack
#                   strings, which is what a context rail is judged on.
#   jailbreak_llms  Shen et al., in-the-wild jailbreak prompts scraped from the
#                   places they circulate, with a matched set of ordinary
#                   prompts from the same collection. The second half is the
#                   part that matters: a benign corpus somebody else built.
require 'fileutils'
require 'digest'
require 'json'
require 'net/http'
require 'tempfile'
require 'uri'

module ExternalCorpusFetch
  MANIFEST_PATH = File.expand_path('../evaluation/benchmark_sources.json', __dir__)

  class IntegrityError < StandardError; end
  class DownloadError < StandardError; end

  # Fetches only manifest-pinned payloads and publishes each one atomically.
  class Fetcher
    def initialize(destination:, sources:, download: nil, output: $stdout)
      @destination = File.expand_path(destination)
      @sources = sources
      @download = download || method(:download)
      @output = output
    end

    def fetch_all
      FileUtils.mkdir_p(@destination)
      @sources.each { |name, source| fetch(name, source) }
    end

    private

    def fetch(name, source)
      validate_name!(name)
      path = File.join(@destination, name)
      if valid?(path, source)
        @output.puts "have #{name} (#{File.size(path) / 1024} KB)"
        return
      end

      @output.print "fetching #{name} ... "
      bytes = @download.call(source.fetch('url'))
      verify!(name, bytes, source)
      atomic_write(path, bytes)
      @output.puts "#{bytes.bytesize / 1024} KB"
    end

    def validate_name!(name)
      return if File.basename(name) == name

      raise IntegrityError, "invalid corpus filename: #{name}"
    end

    def valid?(path, source)
      File.file?(path) &&
        File.size(path) == source.fetch('bytes') &&
        Digest::SHA256.file(path).hexdigest == source.fetch('sha256')
    end

    def verify!(name, bytes, source)
      actual_size = bytes.bytesize
      actual_sha256 = Digest::SHA256.hexdigest(bytes)
      return if actual_size == source.fetch('bytes') && actual_sha256 == source.fetch('sha256')

      raise IntegrityError,
            "#{name} integrity mismatch: got #{actual_size} bytes and sha256 #{actual_sha256}"
    end

    def download(url)
      response = Net::HTTP.get_response(URI(url))
      raise DownloadError, "#{url} answered #{response.code}" unless response.is_a?(Net::HTTPSuccess)

      response.body
    end

    def atomic_write(path, bytes)
      temporary = Tempfile.new([".#{File.basename(path)}", '.tmp'], @destination)
      temporary.binmode
      temporary.write(bytes)
      temporary.flush
      temporary.fsync
      temporary.close
      File.rename(temporary.path, path)
    ensure
      temporary&.close!
    end
  end
end

if $PROGRAM_NAME == __FILE__
  destination = ARGV[0] || File.expand_path('../tmp/external', __dir__)
  manifest = JSON.parse(File.read(ExternalCorpusFetch::MANIFEST_PATH))
  sources = manifest.fetch('external_corpora').fetch('files')

  ExternalCorpusFetch::Fetcher.new(destination: destination, sources: sources).fetch_all

  puts
  puts "into #{File.expand_path(destination)}"
  puts 'now: ruby script/measure_external.rb'
end
