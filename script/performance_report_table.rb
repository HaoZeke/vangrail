# frozen_string_literal: true

module Vangrail
  # Stable Markdown rendering for RiskBenchmark's raw measurements.
  module PerformanceReportTable
    module_function

    def render(report)
      unless report.is_a?(Hash) && report['schema'] == RiskBenchmark::SCHEMA
        raise ArgumentError, "performance report must use #{RiskBenchmark::SCHEMA}"
      end

      [summary(report), kernels(report), scaling(report), artifacts(report), sources(report)].join("\n\n") << "\n"
    end

    def summary(report)
      runtime = report.fetch('runtime')
      parity = report.fetch('parity')
      memory = report.fetch('process_memory_kib')
      startup = report.fetch('startup')
      rows = [
        ['runtime', "#{runtime.fetch('engine')} #{runtime.fetch('ruby')} on #{runtime.fetch('platform')}"],
        ['native parity', parity.fetch('status')],
        ['maximum absolute parity error', parity['max_absolute_error']],
        ['process RSS KiB', memory['rss']],
        ['process high-water KiB', memory['high_water']],
        ['startup ms', startup['latency_ms'] || startup.fetch('status')],
      ]
      markdown_table(%w[measurement value], rows)
    end

    def kernels(report)
      rows = report.fetch('profiles').sort_by do |profile|
        [profile.dig('shape', 'characters'), profile.fetch('implementation'), profile.fetch('kernel')]
      end.map do |profile|
        [
          profile.fetch('kernel'),
          profile.fetch('implementation'),
          profile.dig('shape', 'characters'),
          profile.dig('summary', 'latency_ms', 'median'),
          profile.dig('summary', 'latency_ms', 'p95'),
          profile.dig('summary', 'allocated_objects', 'median'),
          profile.dig('summary', 'rss_kib', 'p95'),
          profile.dig('transport', 'endpoint_calls'),
          profile.dig('transport', 'bytes_transferred'),
        ]
      end
      markdown_table(
        ['kernel', 'implementation', 'characters', 'median ms', 'p95 ms',
         'median allocations', 'p95 RSS KiB', 'endpoint calls', 'bytes transferred'],
        rows,
      )
    end

    def scaling(report)
      rows = report.fetch('scaling_analysis').sort_by do |row|
        [row.fetch('dimension'), row.fetch('implementation')]
      end.map do |row|
        [
          row.fetch('dimension'),
          row.fetch('implementation'),
          row.fetch('work_growth'),
          row.fetch('latency_growth'),
          row.fetch('latency_growth_per_work_growth'),
        ]
      end
      markdown_table(
        ['scaling dimension', 'implementation', 'work growth', 'latency growth', 'normalized growth'],
        rows,
      )
    end

    def artifacts(report)
      values = report.fetch('artifacts')
      rows = [
        ['core library', values.fetch('core_library_bytes'), values.fetch('core_library_sha256')],
        ['model JSON', values.fetch('model_json_bytes'), values.fetch('model_json_sha256')],
        ['native extension', values['native_extension_bytes'], values['native_extension_sha256']],
      ]
      markdown_table(%w[artifact bytes SHA-256], rows)
    end

    def sources(report)
      rows = report.fetch('source_sha256').sort.map { |name, sha256| [name, sha256] }
      markdown_table(%w[source SHA-256], rows)
    end

    def markdown_table(headings, rows)
      lines = [
        "| #{headings.join(' | ')} |",
        "|#{headings.map { '---' }.join('|')}|",
      ]
      rows.each { |row| lines << "| #{row.map { |value| format_value(value) }.join(' | ')} |" }
      lines.join("\n")
    end

    def format_value(value)
      case value
      when nil then 'NA'
      when Float then value.finite? ? format('%.6f', value) : value.to_s
      else value.to_s
      end
    end
  end
end
