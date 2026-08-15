# frozen_string_literal: true

# Regenerates lib/vangrail/confusables_data.rb from the Unicode confusables data.
#
#   gem install unicode-confusable
#   ruby script/generate_confusables.rb
#
# The runtime has no dependencies and this keeps it that way: the table is
# generated here, checked in, and read as a frozen hash. What the gem is for is
# the data behind it, which is UTS #39, revised with every Unicode release and
# far past anything worth maintaining by hand.
#
# The inversion is the part worth understanding. A skeleton maps a string
# toward a canonical form so that two confusable strings compare equal; it does
# not map toward ASCII, so skeletonising a document does not hand you something
# an ASCII pattern will match. What does is the reverse index: for each
# printable ASCII character, take its skeleton, and record every other
# codepoint that skeletonises to the same thing.
#
# Ranges rather than the whole of Unicode, because scanning 1.1 million
# codepoints to find 1400 is slow and the confusables live in known
# neighbourhoods: Latin and Greek and Cyrillic and their supplements, the
# Cherokee syllabary, the CJK compatibility and halfwidth forms, the
# mathematical alphanumerics, and the enclosed alphanumerics.

require 'unicode/confusable'

RANGES = [
  0x00A0..0x058F,   # Latin-1 through Armenian, including Greek and Cyrillic
  0x0590..0x2FFF,   # Hebrew through CJK radicals, including punctuation and letterlike
  0x13A0..0x13FF,   # Cherokee
  0xA000..0xABFF,   # Yi, Vai, Latin extended-D, Cherokee supplement
  0xFB00..0xFFEF,   # alphabetic presentation forms through halfwidth and fullwidth
  0x1D400..0x1D7FF, # mathematical alphanumeric symbols
  0x1F100..0x1F1FF  # enclosed alphanumeric supplement
].freeze

PRINTABLE_ASCII = (33..126).map(&:chr).freeze

def ascii_by_skeleton
  PRINTABLE_ASCII.each_with_object({}) do |char, index|
    index[Unicode::Confusable.skeleton(char)] ||= char
  end
end

def skeleton_of(char)
  Unicode::Confusable.skeleton(char)
rescue StandardError
  nil
end

# A codepoint earns an entry when its skeleton is one an ASCII character also
# has, or when every character of its skeleton is. The second case is the
# ligatures and the enclosed forms, where one codepoint stands for several
# letters.
def build_table
  index = ascii_by_skeleton
  table = {}

  RANGES.each do |range|
    range.each do |codepoint|
      char = begin
        codepoint.chr(Encoding::UTF_8)
      rescue RangeError
        next
      end
      next unless char.valid_encoding?

      skeleton = skeleton_of(char)
      next if skeleton.nil? || skeleton == char

      folded = index[skeleton] || multi(skeleton, index)
      table[char] = folded if folded && folded != char
    end
  end

  table
end

def multi(skeleton, index)
  return nil if skeleton.length < 2

  chars = skeleton.each_char.map do |char|
    sk = skeleton_of(char)
    return nil if sk.nil?

    index[sk] or return nil
  end
  chars.join
end

def render(table)
  entries = table.sort.map do |from, to|
    "      #{from.dump} => #{to.dump}"
  end.join(",\n")

  <<~RUBY
    # frozen_string_literal: true

    module Vangrail
      module Confusables
        # Characters that look like ASCII and are not, mapped to what they
        # imitate.
        #
        # GENERATED FILE. Do not edit by hand; rerun
        # script/generate_confusables.rb when Unicode moves. The policy for
        # using this data lives in confusables.rb, which is hand-written and
        # survives regeneration.
        #
        # Source: Unicode confusables data (UTS #39) via the
        # unicode-confusable gem #{Unicode::Confusable::VERSION},
        # Unicode #{Unicode::Confusable::UNICODE_VERSION}.
        #
        # #{table.size} entries, against the twenty-nine a person can be bothered
        # to write out by hand. The difference is Cherokee, Armenian, the
        # mathematical alphabets, the enclosed forms, and every other
        # neighbourhood nobody remembers while writing a table.
        MAP = {
    #{entries}
        }.freeze

        # Longest first, so a multi-character fold is not pre-empted by a
        # single-character one sharing its first character.
        PATTERN = Regexp.union(MAP.keys.sort_by { |k| -k.length }).freeze
      end
    end
  RUBY
end

table = build_table
path = File.expand_path('../lib/vangrail/confusables_data.rb', __dir__)
File.write(path, render(table))
puts "wrote #{table.size} entries to #{path}"
