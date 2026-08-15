# frozen_string_literal: true

# Readers for the published corpora, shared by the scripts that score against
# them.
#
# The CSV reader is here rather than required, because csv stopped being a
# default gem in Ruby 3.4 and this repository promises to need nothing outside
# the standard library. The fields carry embedded newlines, commas, and doubled
# quotes -- they are jailbreak prompts, so of course they do -- which rules out
# splitting on commas and leaves the ordinary state machine.
require 'json'

module ExternalCorpus
  module_function

  def bipia_injections(dir)
    %w[bipia_text_attack_test.json bipia_code_attack_test.json].flat_map do |name|
      JSON.parse(File.read(File.join(dir, name))).flat_map { |_category, attacks| attacks }
    end.map(&:to_s).reject(&:empty?)
  end

  # A CSV reader, because csv stopped being a default gem in Ruby 3.4 and this
  # repository promises to need nothing outside the standard library. The fields
  # that matter carry embedded newlines, commas, and doubled quotes -- they are
  # jailbreak prompts, so of course they do -- which rules out splitting on
  # commas and leaves the ordinary state machine.
  def each_row(path)
    field = +''
    row = []
    quoted = false
    pending_quote = false

    # each_char rather than indexing: String#[] on UTF-8 walks from the start, so
    # an index loop over a twenty-megabyte file is quadratic and never finishes.
    File.read(path, encoding: 'UTF-8').scrub.each_char do |char|
      if pending_quote
        pending_quote = false
        if char == '"'
          field << '"'
          next
        end
        quoted = false
      end

      if quoted
        char == '"' ? pending_quote = true : field << char
        next
      end

      case char
      when '"' then quoted = true
      when ',' then row << field and field = +''
      when "\n"
        row << field
        yield(row)
        row = []
        field = +''
      when "\r" then nil
      else field << char
      end
    end
    row << field unless field.empty? && row.empty?
    yield(row) unless row.empty?
  end

  def prompts(dir, name, limit)
    header = nil
    column = nil
    out = []
    each_row(File.join(dir, name)) do |row|
      if header.nil?
        header = row
        column = header.index('prompt')
        raise "no prompt column in #{name}: #{header.inspect}" unless column

        next
      end
      next if out.size >= limit

      value = row[column].to_s
      out << value unless value.empty?
    end
    out
  end

  def jailbreak_prompts(dir, limit = 100_000)
    prompts(dir, 'jailbreak_prompts_2023_12_25.csv', limit)
  end

  def regular_prompts(dir, limit = 100_000)
    prompts(dir, 'regular_prompts_2023_12_25.csv', limit)
  end
end
