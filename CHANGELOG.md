# Changelog

All notable changes to this project are recorded here, in the format of
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

`cog bump` writes the released sections from the commit history. Everything
below `Unreleased` is written by hand until it is released.

## [Unreleased]

Nothing has been released yet. This section describes what exists.

### Added

- Rails as ordinary Ruby objects, each with one `call` method, returning a
  `Result`. A regex check, a safety classifier, a Colang flow, and a call out
  to a NeMo Guardrails server all use the same protocol and sit in one ordered
  list.
- Three rail sides. `:input` reads what the user typed, `:output` reads what
  the model wrote, and `:context` reads a retrieved document before it reaches
  a prompt. The third is the side an attacker can usually reach without
  touching the application at all.
- Three result statuses: `passed`, `modified`, and `blocked`. A rail can
  rewrite text rather than only accept or refuse it, and the engine threads a
  rewrite through the rails that follow.
- `certain?`, orthogonal to the status. A rail that is off, disabled, or
  unreachable returns passed with `certain?` false, so an application can tell
  "checked and clean" from "not checked".
- `Engine#screen`, which runs a set of retrieved documents through the context
  rails and reports what survived. A poisoned document is dropped and named
  rather than failing the whole turn.
- Deterministic offline rails: `Rails::Pattern`, `Rails::Secrets` (which
  redacts rather than blocks), and `Rails::InjectedInstructions`.
- Model-backed rails: `Rails::GuardModel` for safety classifiers,
  `Rails::SelfCheck` for a written policy, and `Rails::Grounding` for whether
  an answer follows from its passages.
- `Spotlight`, which marks retrieved text as data by delimiting, datamarking,
  or encoding, with a delimiter tag that is random per request.
- A Colang parser and interpreter for the documented subset, so a NeMo
  Guardrails configuration folder runs in this process. Anything outside the
  subset raises at load rather than being skipped.
- `Client` for an existing NeMo Guardrails server, using `/v1/checks` where it
  exists and falling back once to a chat completion with generation off.
- A provider abstraction that prefers a local proxy, and picks the rail class
  from what the endpoint can actually serve.
- An in-process result memo, bounded at 256 entries, which never stores an
  uncertain result.
- An injection corpus of 60 attacks across 12 shapes and 5 positions in real
  documentation prose, scored together with a benign pass rate.

### Fixed

- The grounding rail was routed through a safety classifier, which answers with
  its own label tokens whatever it is asked, so every grounding check returned
  an unparsable answer. It now uses an instruct-model judge.
- A grounding placeholder was constructed with `:grounding` as a rail side.
  Sides are input, context, and output; a rail name is not one.
- `Provider.resolve` read a registry installed from the process environment, so
  a caller passing an environment hash could not describe a gateway in it.
- A key-file override was tried before the configured path rather than
  replacing it, and a pass-entry override was ignored, which left no way to run
  without credentials on a machine that has some.

### Changed

- No institution's endpoint ships in the gem. Shared gateways are registered by
  the application that has one, or described entirely through environment.
- `Spotlight#encode` uses `pack('m0')` rather than the `base64` library, which
  stopped being a default gem in Ruby 3.4.
