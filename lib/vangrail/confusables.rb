# frozen_string_literal: true

require_relative 'confusables_data'

module Vangrail
  # Folds characters that imitate ASCII back to the ASCII they imitate.
  #
  # The data is generated from the Unicode confusables file (UTS #39) and lives
  # in confusables_data.rb. This is the policy that uses it, kept apart so
  # regenerating the table cannot overwrite a decision.
  #
  # The decision worth writing down is which words to fold. Folding everything
  # turns a page of Russian into ASCII noise: "Кластер" becomes "Kлacтep",
  # which is not Russian, not English, and not what anybody wrote. It happens
  # to be harmless here, because a folded variant is only ever shown to a
  # pattern and never to a reader, but it is the wrong thing to be doing and it
  # widens the surface for an accidental match.
  #
  # What an imitation attack actually looks like is a *mixed* word: Latin
  # letters with one or two lookalikes dropped in, so that "system" reads as
  # "system" and is not. A word written entirely in Cyrillic is not imitating
  # anything; it is a word in Cyrillic. UTS #39 draws the same line and calls
  # it mixed-script detection.
  #
  # So `fold` leaves single-script words alone and folds the mixed ones. That
  # keeps genuine multilingual documentation intact and still catches the
  # attack, which the corpus asserts in both directions.
  module Confusables
    # A run of non-space characters. Folding is decided per word because that
    # is the unit the mixing happens in.
    WORD = /\S+/

    module_function

    # Every word that mixes ASCII with imitators, folded. Text with no
    # imitators at all is returned untouched and costs one match.
    def fold(text)
      body = text.to_s
      return body unless body.match?(PATTERN)

      body.gsub(WORD) { |word| mixed?(word) ? fold_word(word) : word }
    end

    # Folds regardless of mixing. For a caller that has already decided the
    # text should be Latin, and for measuring what the policy costs.
    def fold_all(text)
      body = text.to_s
      return body unless body.match?(PATTERN)

      fold_word(body)
    end

    def confusable?(text)
      text.to_s.match?(PATTERN)
    end

    # A word imitating ASCII carries both: at least one ASCII letter or digit,
    # and at least one character pretending to be one.
    def mixed?(word)
      word.match?(/[A-Za-z0-9]/) && word.match?(PATTERN)
    end

    def fold_word(word)
      word.gsub(PATTERN) { |char| MAP.fetch(char, char) }
    end
  end
end
