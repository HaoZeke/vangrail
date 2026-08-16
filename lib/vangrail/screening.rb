# frozen_string_literal: true

require_relative 'origin'

module Vangrail
  # What Engine#screen returns. `certain` means what it means on a Result:
  # false says a rail did not reach a decision about some document, so
  # "nothing was rejected" is not evidence that nothing was wrong.
  Screening = Struct.new(:kept, :rejected, :certain, :reason, keyword_init: true) do
    def certain?
      certain
    end

    def rejected?
      !rejected.empty?
    end

    def cells
      kept.map { |document| Cell.data(Cell.text_of(document)) }
    end

    def to_h
      {
        'kept' => kept.size,
        'rejected' => rejected.map { |r| r[:result].to_h },
        'certain' => certain?,
        'reason' => reason,
      }.compact
    end

    # Screens a set of retrieved documents and reports what survived.
    #
    # A document that fails is dropped rather than failing the whole turn. One
    # poisoned wiki page should cost a reader that page, not their answer, and
    # an application that refuses outright teaches its readers that the
    # guardrail is the problem.
    def self.run(engine, documents, **context)
      kept = []
      rejected = []
      uncertain = nil

      Array(documents).each_with_index do |document, index|
        result = engine.check_context(text_of(document), **context, document: document, index: index)
        uncertain ||= result unless result.certain?
        if result.blocked?
          rejected << { document: document, result: result }
        else
          kept << (result.modified? ? replace_text(document, result.content) : document)
        end
      end

      new(kept: kept, rejected: rejected, certain: uncertain.nil?, reason: uncertain&.reason)
    end

    def self.text_of(document)
      Cell.text_of(document)
    end

    # A context rail may rewrite a document rather than reject it, so the
    # replacement has to go back into the shape the caller passed in.
    def self.replace_text(document, content)
      return content.to_s unless document.is_a?(Hash)

      key = document.key?('text') ? 'text' : :text
      document.merge(key => content.to_s)
    end
  end
end
