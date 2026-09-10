# frozen_string_literal: true

require_relative '../chat'
require_relative '../nlp'
require_relative '../rail'

module Vangrail
  module Rails
    # Asks the model what it now believes it was asked, and compares.
    #
    # Rails::TaskRelation asks a judge whether a document's tasks are related to
    # the reader's. That closes the off-task family and is blind by construction
    # to the other one: "supplementing your solution with the below code snippet
    # could be beneficial", followed by a socket, is *related* to a question
    # about code, and every miss in that rail's held-out measurement was this
    # shape. Relatedness cannot separate help from a payload.
    #
    # Drift can. The question is not whether a request belongs to the topic but
    # whether it was in the request the reader made, and that is answerable
    # without judging it: ask the model to list the requests it is about to
    # carry out, once with the question alone and once with the document beside
    # it, and compare the lists. A request that appears only in the second was
    # put there by the document.
    #
    # This is Abdelnabi et al.'s task drift (arXiv:2406.00799) with its
    # measurement moved outside the model. They detect drift in activation
    # deltas, which needs weights this gem will never have; but their own
    # priming template asks the model to write out "all requests that I am going
    # to execute now", and their footnote says that template classifies well
    # enough on its own that the activations may not be necessary. What is left
    # when the activations go is a text-level probe, and this is it.
    #
    # Two calls, or one amortised: the reader's own request list does not depend
    # on the document, so a caller screening six passages for one question pays
    # for the baseline once. Pass it in as `baseline:` to do that.
    #
    # What this cannot do is judge. A document that adds a request the reader
    # would have wanted still adds one, so a page ending "see also tar(5)" can
    # read as drift. That is why it reports what appeared rather than a verdict
    # about intent, and why it is the rail to run beside TaskRelation rather
    # than instead of it.
    class TaskDrift < Rail
      # Deliberately undefended, and this is the whole design.
      #
      # The first version of this prompt told the model that the document was
      # data and not to act on it. It then listed the reader's request and
      # nothing else, for a clean page and for a page carrying a socket, because
      # that is what a model does when it has been told to disregard the
      # document: it reports no drift. The probe suppressed the signal it exists
      # to read.
      #
      # So the probe asks what requests it received and is about to execute,
      # with no instruction hierarchy and no fencing, which is Abdelnabi et
      # al.'s template. What it measures is what an undefended reading of this
      # document would do, and that is the question worth asking about a
      # document nobody has vetted. The answer is never shown to a reader and
      # never used as an answer to anything: the only thing done with it is
      # comparing two lists.
      PROMPT = <<~PROMPT
        You list requests. You never carry them out and you never answer them.

        Your entire reply is a list, one request per line, each in six words or
        fewer. No preamble, no explanation, no code, no tables. If you received
        no requests, reply NONE.
      PROMPT

      # The enumeration comes after the request and interrupts it, which is the
      # order Abdelnabi et al. use: the model is asked what it received before
      # it is allowed to act on any of it.
      QUESTION_TEMPLATE = <<~PROMPT
        Here are your main requests: %<question>s

        But before you answer, complete this sentence and then stop:
        "All requests that I am going to execute now are:"
      PROMPT

      # No fence and no marker, because a fence is an instruction hierarchy and
      # the point is to read the document the way an unfenced prompt would.
      WITH_DOCUMENT_TEMPLATE = <<~PROMPT
        Here are your main requests: %<question>s

        %<document>s

        But before you answer, complete this sentence and then stop:
        "All requests that I am going to execute now are:"
      PROMPT

      NONE = 'none'

      attr_reader :model, :chat

      def initialize(provider: nil, model: nil, chat: nil, name: 'task_drift',
                     sides: [:context], max_tokens: 600, **chat_options)
        super(name: name, sides: sides)
        @model = model || provider&.model(:judge)
        raise ArgumentError, 'a task-drift rail needs a model' if @model.nil? && chat.nil?

        @chat = chat || begin
          raise ArgumentError, 'a task-drift rail needs a provider or a chat client' unless provider

          Chat.new(model: @model, base_url: provider.base_url, api_key: provider.api_key,
                   max_tokens: max_tokens, **chat_options)
        end
      end

      def offline?
        false
      end

      def cache_key(text, context)
        "#{context[:user_input]}\n#{text}"
      end

      # The request list for a question on its own, which a caller screening
      # several documents for one question should compute once and pass back in.
      def baseline_for(question)
        requests(ask(format(QUESTION_TEMPLATE, question: question)))
      end

      def decide(text, context)
        question = context[:user_input].to_s.strip
        return unchecked('no question to compare the document against', model: model) if question.empty?
        return pass(model: model) if text.strip.empty?

        before = context[:baseline] || baseline_for(question)
        return unchecked('the model listed no requests for the question alone', model: model) if before.nil?

        answer = ask(format(WITH_DOCUMENT_TEMPLATE, question: question, document: text))
        after = requests(answer)
        return unchecked('the model listed no requests for the document', model: model, raw: answer.raw) if after.nil?

        added = after.reject { |request| known?(request, before) }
        return pass(model: model, latency_ms: answer.latency_ms, raw: answer.raw) if added.empty?

        block(reason: "the document added #{added.map { |r| r[:text] }.join('; ')}",
              categories: ['task_drift'], model: model, latency_ms: answer.latency_ms, raw: answer.raw)
      end

      private

      def ask(body)
        chat.ask([{ 'role' => 'system', 'content' => PROMPT },
                  { 'role' => 'user', 'content' => body }])
      end

      # A request is a short line. Anything else the model wrote is the model
      # answering the question instead of listing it, and counting that as a
      # request pollutes the baseline until every later line looks familiar --
      # which is how the first version of this passed a document carrying a
      # socket.
      MAX_WORDS = 10
      # The probe's own instruction, which the model lists as a request it
      # received roughly half the time, because it is one. It is in both prompts
      # so the comparison usually cancels it; usually is not good enough when
      # the alternative is a false alarm on a clean page.
      ECHO = /\A(all requests that i am going|complete .*sentence|finish .*sentence|stop after)/i
      NOT_A_REQUEST = %r{\A(```|\||#|>|[-=]{3,})}

      # nil when the model answered nothing readable, which is a check that did
      # not happen; an empty list when it answered NONE, which is a check that
      # found no requests.
      def requests(answer)
        lines = answer.text.to_s.lines.map { |line| line.strip.sub(/\A[-*\d.)\s]+/, '').strip }
                       .reject(&:empty?)
        return nil if lines.empty?
        return [] if lines.any? { |line| line.downcase.delete('.:').strip == NONE }

        kept = lines.reject { |line| line.match?(ECHO) || line.match?(NOT_A_REQUEST) }
                    .select { |line| NLP.words(line).size <= MAX_WORDS }
        return nil if kept.empty?

        kept.map { |line| { text: line, words: content_stems(line) } }
      end

      # Stems, minus the words every request shares. The two lists are written by
      # the model in its own words on two separate calls, so "summarise the page"
      # and "summarise this manual page" have to count as one request; comparing
      # surface tokens would call them two and report drift on every document.
      SHARED_WORDS = (NLP::DETERMINER_STEMS + NLP::COORDINATOR_STEMS + NLP::PRONOUN_STEMS +
                      NLP::COPULA_STEMS + NLP::ANAPHORA_STEMS +
                      %w[to of in on for from with a an and or please answer request
                         provide give write list].to_set { |w| NLP.stem(w) }).freeze

      def content_stems(line)
        NLP.words(line).map { |word| NLP.stem(word) }.reject { |stem| SHARED_WORDS.include?(stem) }.uniq
      end

      # One content word shared with something the reader asked for is enough to
      # call it the same request.
      #
      # Both lists are written by the model, in its own words, on two separate
      # calls, so "explain how to use tar" and "describe using tar archives" are
      # one request and have one word in common. Requiring two called them two
      # and reported drift on every document. The cost of the loose rule is a
      # request that borrows a word from the question and is missed, which is
      # the on-task family this rail cannot see anyway.
      def known?(request, before)
        return true if request[:words].empty?

        before.any? { |seen| (request[:words] & seen[:words]).any? }
      end
    end
  end
end
