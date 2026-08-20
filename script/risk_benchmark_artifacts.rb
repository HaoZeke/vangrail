# frozen_string_literal: true

require 'digest'
require 'json'

module Vangrail
  # Artifact and source identities attached to every performance report.
  module RiskBenchmarkArtifacts
    private

    def artifacts(model)
      extension = $LOADED_FEATURES.detect { |path| File.basename(path).start_with?('vangrail_native.') }
      extension = nil unless extension && File.file?(extension)
      model_json = JSON.generate(model.to_h)
      {
        'core_library_bytes' => library_bytes,
        'core_library_sha256' => library_digest,
        'model_json_bytes' => model_json.bytesize,
        'model_json_sha256' => Digest::SHA256.hexdigest(model_json),
        'native_extension_bytes' => extension && File.size(extension),
        'native_extension_sha256' => extension && Digest::SHA256.file(extension).hexdigest,
      }
    end

    def library_bytes
      library_files.sum { |path| File.size(path) }
    end

    def library_digest
      root = File.expand_path('..', __dir__)
      digest = Digest::SHA256.new
      library_files.each do |path|
        relative = path.delete_prefix("#{root}/")
        digest << relative << "\0" << Digest::SHA256.file(path).hexdigest << "\n"
      end
      digest.hexdigest
    end

    def library_files
      root = File.expand_path('..', __dir__)
      Dir[File.join(root, 'lib', '**', '*.{rb,json}')]
    end

    def source_digests
      root = File.expand_path('..', __dir__)
      {
        'benchmark_risk' => file_digest(File.join(root, 'script', 'benchmark_risk.rb')),
        'performance_report_table' => file_digest(File.join(root, 'script', 'performance_report_table.rb')),
        'risk_benchmark_artifacts' => file_digest(File.join(root, 'script', 'risk_benchmark_artifacts.rb')),
        'risk_benchmark_cli' => file_digest(File.join(root, 'script', 'risk_benchmark_cli.rb')),
        'risk_benchmark_scaling' => file_digest(File.join(root, 'script', 'risk_benchmark_scaling.rb')),
        'linear_model' => file_digest(File.join(root, 'lib', 'vangrail', 'linear_model.rb')),
        'native_source' => file_digest(File.join(root, 'ext', 'vangrail_native', 'src', 'lib.rs')),
        'native_lock' => file_digest(File.join(root, 'ext', 'vangrail_native', 'Cargo.lock')),
      }
    end

    def file_digest(path)
      Digest::SHA256.file(path).hexdigest
    end
  end
end
