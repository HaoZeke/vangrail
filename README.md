<h1 align="center">
  <img src="docs/assets/vangrail-mark.jpg" width="420" alt="vangrail: a W-beam crash barrier">
</h1>

<p align="center">
  <img src="docs/assets/vangrail-icon.jpg" width="96" alt="vangrail icon: the beam end and amber lamp">
</p>

# vangrail

*Dutch for the steel barrier at the edge of a road. It does not stop you
driving; it stops one bad moment becoming a worse one.*

vangrail is guardrails that run inside a Ruby process. Input, context, and
output rails, against any OpenAI-compatible endpoint, with no Python service
in the path and nothing outside the standard library at runtime.

- **Documentation:** [docs/orgmode/index.org](docs/orgmode/index.org)
- **Tutorial:** [Stop an injected instruction in ten minutes](docs/orgmode/tutorials/first-rails.org)
- **Source:** https://github.com/HaoZeke/vangrail
- **RubyGems:** https://rubygems.org/gems/vangrail
- **API (YARD):** https://haozeke.github.io/vangrail/
- **Contributing:** [CONTRIBUTING.md](CONTRIBUTING.md)
- **Changelog:** [CHANGELOG.md](CHANGELOG.md)

It provides:

- a rail protocol: one object, one method, three statuses (`passed` /
  `modified` / `blocked`) plus `certain?`
- three sides: the question, the retrieved documents, and the model's answer
- deterministic rails that need no network
- model-backed rails that call a local proxy first, then whatever endpoint
  you name
- provenance-labelled values and a locked plan for monitored tool calls
- versioned score providers for optional encoder, embedding, and judge readers
- checksum-verified joint-risk and evaluation artifacts
- a Colang 1.0 rail-flow subset executed in process

Detection and authority are separate. A risk result may restrict an explicit
tool grant, but it cannot create one. Heavy readers remain optional processes
or endpoints; the core gem does not gain their runtime dependencies. The
optional `vangrail-native` gem accelerates the hashed linear kernel without
changing the Ruby fallback.

## Install

Ruby 3.1 or newer. There is no bundle.

```bash
gem install vangrail
```

From a clone:

```bash
git clone https://github.com/HaoZeke/vangrail.git
cd vangrail
ruby -Ilib -e 'require "vangrail"; puts Vangrail::VERSION'
```

## Quickstart

No API key. The deterministic rails run; model-backed ones report themselves
missing rather than pretending they ran.

```ruby
require 'vangrail'

engine = Vangrail.from_env
puts engine.describe

engine.check_input('How do I submit a GPU job?').passed?   # => true
answer = engine.check_output('Set api_key=sk-live-9c2f1 in the file.')
answer.modified?   # => true
answer.content     # => "Set api_key=[redacted] in the file."
```

A custom rail is the same protocol as the built-in ones:

```ruby
class TicketRail < Vangrail::Rail
  def decide(text, _context)
    return pass if text.match?(/EINF-\d+/)

    block(reason: 'no ticket id')
  end
end
```

## Next

| I want to… | Go here |
|---|---|
| Learn the three sides by running five short programs | [Tutorial](docs/orgmode/tutorials/first-rails.org) |
| Point the model rails at a local proxy | [llmlite](docs/orgmode/howto/using-llmlite.org) |
| Name any other endpoint | [Choosing an endpoint](docs/orgmode/howto/choosing-an-endpoint.org) |
| Screen retrieved documents | [Screening](docs/orgmode/howto/screening-documents.org) |
| Enforce arguments, sinks, confirmation, and use counts | [Enforce tool calls](docs/orgmode/howto/enforcing-tool-calls.org) |
| Understand optional readers and joint risk | [Detection is not authority](docs/orgmode/explanation/two-planes.org) |
| Look up a variable or a rail | [Environment](docs/orgmode/reference/environment.org), [rails](docs/orgmode/reference/rails.org) |
| Read why `certain?` exists | [Three statuses](docs/orgmode/explanation/three-statuses.org) |
| Read what this does not do | [Coverage](docs/orgmode/explanation/coverage.org) |

The long argument (evidence, measurements, reading list) lives under
[docs/orgmode/explanation/](docs/orgmode/explanation/three-statuses.org),
not on this page.

## Tests

```bash
gem install minitest
rake test
```

Stdlib minitest, one process, no bundle, no outbound network. A single file
is `ruby -Ilib test/test_engine.rb`.

## License

MIT. See [LICENSE](LICENSE).
