# frozen_string_literal: true

# A benign corpus of real technical documentation, read off the machine.
#
#   require_relative 'local_corpus'
#   LocalCorpus.documents(limit: 20_000)
#
# The corpora shipped with the tests are hand-written, forty-eight documents
# long, and were composed by the same person who wrote the rails. That is enough
# to catch a rule that flags its own handbook and nowhere near enough to measure
# a false-alarm rate: a rail that fires on one page in a thousand scores zero on
# forty-eight documents, and zero is the number that made two rails look
# valuable in the evidence table.
#
# What a false-alarm rate needs is real prose, in volume, that nobody wrote for
# this purpose. Installed documentation is exactly that. It is technical, it is
# adversarial by accident in all the ways that matter -- shell commands,
# environment variables, paths, flags, security advice, warnings telling the
# reader to ignore things -- and there are tens of thousands of pages of it on
# any developer's machine.
#
# Nothing is checked into the repository. The text belongs to its authors under
# their own licences, and a corpus of that size does not belong in a gem
# whatever the licence says. The scripts read what is installed and check in the
# counts, the way the confusables table checks in data rather than the Unicode
# database.
module LocalCorpus
  MAN_ROOT = '/usr/share/man'
  DOC_ROOT = '/usr/share/doc'

  # Rendering a man page costs a groff invocation, so the work is threaded. It
  # is IO-bound, which is the case Ruby threads are actually good at.
  THREADS = 8

  module_function

  # Rendered man pages plus documentation text files, as strings.
  #
  # Collected rather than streamed, which is fine for a few hundred and is not
  # what a run over twenty thousand should use: the corpus is a third of a
  # gigabyte of text and there is no reason to hold it.
  def documents(limit: 20_000, **kwargs)
    out = []
    each_document(limit: limit, **kwargs) { |text| out << text }
    out
  end

  # One document at a time, which is how anything measuring the whole corpus
  # should read it.
  def each_document(limit: 20_000, man: true, docs: true, quiet: false, truncate: 20_000)
    paths = []
    paths.concat(man_paths.first((limit * 0.85).to_i)) if man
    paths.concat(doc_paths.first(limit - paths.size)) if docs
    warn "reading #{paths.size} documents" unless quiet

    stream(paths, truncate) { |path, text| yield(text, path) }
  end

  def man_paths
    Dir.glob(File.join(MAN_ROOT, 'man*', '*')).select { |p| File.file?(p) }.sort
  end

  # Text-shaped files only. A changelog and a README are prose; a licence is a
  # form, and there are thousands of identical copies of it.
  def doc_paths
    Dir.glob(File.join(DOC_ROOT, '**', '*'))
       .select { |p| File.file?(p) && p.match?(/\.(md|txt|rst)\z|README|CHANGELOG|NEWS/i) }
       .grep_v(/LICEN[CS]E|COPYING/i)
       .sort
  end

  # Rendered by a pool of threads, handed to the caller one at a time on the
  # main thread, so a measurement can hold counters without locking them.
  def stream(paths, truncate)
    queue = Queue.new
    paths.each { |path| queue << path }
    out = Queue.new

    workers = Array.new(THREADS) do
      Thread.new do
        while (path = begin
          queue.pop(true)
        rescue ThreadError
          nil
        end)
          text = render(path)
          out << [path, text[0, truncate]] if text && text.length > 200
        end
        out << :done
      end
    end

    finished = 0
    while finished < THREADS
      item = out.pop
      if item == :done
        finished += 1
        next
      end
      yield(item.first, item.last)
    end
    workers.each(&:join)
  end

  def render(path)
    return read_text(path) unless path.match?(/\.\d[^.]*(\.gz|\.bz2|\.xz)?\z/)

    text = `man --no-hyphenation --no-justification -P cat #{shell_quote(path)} 2>/dev/null`
    text.empty? ? nil : text
  rescue StandardError
    nil
  end

  def read_text(path)
    return nil if File.size(path) > 400_000

    File.read(path, encoding: 'UTF-8').scrub
  rescue StandardError
    nil
  end

  def shell_quote(path)
    "'#{path.gsub("'", "'\\\\''")}'"
  end
end
