# Changelog

All notable changes to this project are recorded here, in the format of
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

`cog bump` writes the released sections from the commit history. Everything
below `Unreleased` is written by hand until it is released.

- - -
## v0.1.0 - 2026-08-15
#### Features
- (**ask**) guardrails on every turn, and an honest BYOK panel - (6b32345) - *HaoZeke*
- (**builder**) context rails on by default - (cae4844) - *HaoZeke*
- (**config**) run retrieval and context flows as context rails - (be2a7f8) - *HaoZeke*
- (**guardrails**) memoize rail verdicts in process - (827e6af) - *HaoZeke*
- (**guardrails**) rationales from AprielGuard, and a live smoke target - (3c2e54f) - *HaoZeke*
- (**guardrails**) Ruby bindings for NeMo Guardrails - (0611bf8) - *HaoZeke*
- (**stream**) hand out only unseen text after a mid-stream rewrite - (6354c4f) - *HaoZeke*
- stream-time rails, conversation history, and encoded-injection decoding - (adeaf3e) - *HaoZeke*
- take the confusables table from Unicode instead of from memory - (3e86db1) - *HaoZeke*
- the safe prompt shape in one call - (53c4c33) - *HaoZeke*
- detect an injection by whether it worked, and report that it does not - (35eb30e) - *HaoZeke*
- strip what executes, refuse what only costs - (ebbae80) - *HaoZeke*
- keep the reader's own details out of the request - (43cb8ef) - *HaoZeke*
- read the parts of a page nobody looks at - (409a104) - *HaoZeke*
- a fake conversation, and a marker that proves a leak - (2f85b4b) - *HaoZeke*
- ask a model where the conversation is going - (bf1edef) - *HaoZeke*
- make the new rails reachable from the environment - (a29cb2c) - *HaoZeke*
- judge the sequence, not just the message - (3abbee3) - *HaoZeke*
- read the text an attacker meant rather than the text they wrote - (b33933c) - *HaoZeke*
- refuse the URLs an answer has no business emitting - (6414f8d) - *HaoZeke*
- check the answer while it is still arriving - (a850752) - *HaoZeke*
- rails for the retrieved document, not just the question and the answer - (d264329) - *HaoZeke*
- a rails engine, not a REST client - (71e6acf) - *HaoZeke*
#### Bug Fixes
- (**guardrails**) route grounding to a judge model, not the classifier - (6d68349) - *HaoZeke*
- (**stream**) hand out only text a rail has actually read - (4faaf0b) - *HaoZeke*
- commit the two config files git was hiding - (2bc86ec) - *HaoZeke*
- report the rail that ran, not the rail that was never built - (da2b3ef) - *HaoZeke*
- an empty dialogue is an answer, not a missing one - (9bf432d) - *HaoZeke*
- a base64 blob ending in + lost its last character - (6aa1207) - *HaoZeke*
#### Performance
- (**ask**) overlap the rails with the work they guard - (db9267a) - *HaoZeke*
#### Documentation
- (**guardrails**) document the grounding judge model and measured rail latency - (41ec631) - *HaoZeke*
- (**readme**) emit StreamGuard#take rather than the raw chunk - (dc893c5) - *HaoZeke*
- (**readme**) the third side, registered gateways, and the measured score - (77878d7) - *HaoZeke*
- publish the YARD class reference on GitHub Pages - (d9841b5) - *HaoZeke*
- map the rails onto the published categories, gaps included - (fc08a0e) - *HaoZeke*
- write down what the new rails do and what they do not - (4cce4fb) - *HaoZeke*
- a Diataxis tree, with the tutorial that needs no key - (167d8ba) - *HaoZeke*
- changelog, code of conduct, ownership, and the release path - (3d482e3) - *HaoZeke*
#### Tests
- print the injection-corpus pair from the shipped rail - (babcaa2) - *HaoZeke*
- the prompt shape does help, at a sample size that can tell - (93f472d) - *HaoZeke*
- measure the prompt itself, and report that the result is inconclusive - (2172977) - *HaoZeke*
- measure the trajectory judge against a live endpoint - (23ea2b8) - *HaoZeke*
- measure the corpus again with the encodings applied - (11f10cb) - *HaoZeke*
- an injection corpus, scored on both numbers at once - (4f9209d) - *HaoZeke*
#### Refactoring
- (**providers**) no institution's endpoint ships in the gem - (1da7dca) - *HaoZeke*
- rename to vangrail - (c3ed8b2) - *HaoZeke*
#### Miscellaneous
- (**changelog**) add the cocogitto separator so the first bump can write - (31278b1) - *HaoZeke*
- (**deps**) bump the dependencies group with 3 updates - (332a206) - dependabot[bot]
- ignore generated YARD output and local agent state - (a568819) - *HaoZeke*
- coverage, opt-in and guarded - (c862175) - *HaoZeke*
- CI, lint, and a style settled once - (4486a5b) - *HaoZeke*

- - -


## [Unreleased]

### Added

- `vangrail` CLI and `Vangrail::Server` speak the same JSON envelope as
  `Engine#check_*`, `#screen`, and `#assess`. Other languages call this
  process; they do not embed MRI.

### Fixed

## v0.2.0 - 2026-08-16

The rail protocol is `#decide`. `#call` scrubs bytes first and then
delegates. Builder and Engine are separate objects. Judges that cannot
parse an answer go through `unchecked`. The rest of this section is what
landed between v0.1.0 and this tag.

### Fixed

- `LinearModel.load` refuses a bucket count that is not a positive integer
  at most `2**20`, so a hostile file cannot grow the weight table.
- The four-gram stride is written into the model file and read back
  (default 2, so older files still load).
- Stem-cache lookup is membership by key, so a falsey cached stem cannot
  evict a different word. An evicted lexicon form still stems correctly.
- `NLP.clauses` on invalid UTF-8 does not raise.
- `ResultCache` is ordinary UTF-8. The source file no longer carries NUL
  bytes in a composite key; side, name, and key sit on an ordered Hash.
- The engine keys a memo on `Rail.usable(text)`, not the raw body. A
  socket-tagged retry and a body carrying a NUL share the slot the first
  verdict already filled.
- `ColangFlow#offline?` is false. Its actions can hit the network, so a
  config-folder engine is not reported as free.

- `Engine#assess` no longer treats an unread language as a clean page.
  When `Rails::Language` reports that the text is outside the lexicons,
  silence from the word rails is abstention rather than innocence, and
  the posterior stays at the prior.
- `Rails::Language` now sits on the input side as well as on context, so
  a long question in an unread language no longer certain-passes
  `check_input`.
- Dutch verb-final subordinates match the ordered paraphrase templates:
  "dat je de richtlijnen negeert" is an override. The coordinated
  handbook sentence that made the rule ordered stays clean.
- `Hidden` and `Obfuscation` no longer turn an inner `certain?` false
  into a clean pass. An inner `:modified` rewrites the span (or the
  decoded run) inside the page and carries a `hidden:` / `encoded:`
  category. The child's span is not the document.
- `Trajectory` with no `:history` key is abstention, the same contract
  `Escalation` already had. A short dialogue that was handed in is still
  a certain pass.
- Phrase-table concepts go through negation. "this is not the system
  prompt" no longer contributes `:secret`; "without restrictions" still
  does, because the negator is the phrase.
- "Ignore the above and …" names an instruction. The determiner-plus-prior
  rule no longer requires the prior word to be clause-final.
- `Rails::Language` reads clause by clause, so a German paragraph inside
  an English page is unread. Character n-gram rank profiles (Cavnar and
  Trenkle) name an unread language in the twelve-to-twenty-three token
  band, where function-word counts stay quiet.
- Markup, budget, secrets, canary, personal data, and exfiltration set
  `language_agnostic?`, so their silence on an unread page is still
  silence. Hidden and Obfuscation wrap lexicon rails and do not.
- `Rails::Bayes` treats a score between 0 and the threshold as
  abstention. That band is the one the calibration already reports as
  mixed (22 attacks and 8 ordinary pages). Above the threshold no
  held-out benign document landed; at or below 0 no held-out attack did.
- Escalation, PromptLeak frames, and ManyShot role headers read Dutch
  as well as English. A Dutch retry after a refusal, a `mijn instructies`
  frame, and a `gebruiker:` / `assistent:` paste are no longer silent.
- `Engine#assess(confidence:)` uses the Beta-bounded bits
  `Posterior.combine` already knew how to compute. If the bound and the
  point estimate disagree about the action, the judgement is uncertain:
  48 benign pages did not identify it.
- `Session#fold` of a Result with no measured operating point is 0
  bits. An unmeasured rewrite is not a leak.
- `Profile.resolve` raises when a named profile is given extra `allow:`
  or `deny:`. Deny-wins merge is only for composing from hashes. Extra
  allow on `:off` does not silently grant a tool.

### Changed

- Colang `stop` is a return tag, and a missing `define bot` or flow raises
  `ColangError` at load instead of `UnknownAction` at run.
- `Builder` is its own file. `GUARDRAILS_RAILS` names that are not in the
  known set raise `ArgumentError` instead of disappearing through
  intersection.
- `Engine#rails` raises on an unknown side. `:sideways` is not a quiet
  trip through the output list.
- A rail implements `#decide`. `#call` is the template: it scrubs the
  bytes first and then calls `#decide`. A subclass that defines `#call`
  instead skips the scrub.
- `Rail#offline?` defaults to true. Networked is the rare case and has
  to say so.

- A page carrying bytes that are not valid UTF-8 now comes back `modified`
  rather than `passed`: the byte is stripped from what the reader and the model
  are handed, which is the contract zero-width characters have always had.
  Anything branching on `modified` should know it can now mean a rewrite that is
  not a redaction.
- `Engine#assess` reads the table written by
  `script/measure_evidence_external.rb`. `script/measure_evidence.rb` writes
  `tmp/handbook_evidence.rb` and does not overwrite the shipped schema.
  `script/baseline_external.rb` reports its bag-of-stems classifier under
  `bag_*` keys, not `bayes_*`.


- The context rails catch 0 of 125 published BIPIA injections. Those attacks are
  off-task instructions carrying no override, disclosure, or concealment, which
  is a coverage gap the documentation never named rather than a detection
  failure; the shipped corpus scores the same rails at 60 of 60 because it was
  written out of the same idea of an attack.
- Screening drops 2.32% of real documentation. The hand-written benign corpus
  reported 0 of 48 and could not have found this.
- `injection_patterns` is anti-informative on real prompts: it fires on 5.3% of
  ordinary ones and 2.5% of in-the-wild jailbreaks, so a hit from it is worth
  −1.6 bits.
- The base rate is measured rather than assumed: zero injections in 18,258 real
  documents bounds it at one in 9,506 with 95% confidence.

### Added

- `Profile` (`workspace`, `strict`, `read_only`, `off`): named
  postures pinned for the conversation, copied from Grok Build's
  sandbox and permission model. Deny globs always win over allow and
  over the plan when composing from hashes. A named profile plus extra
  `allow:` / `deny:` is refused. `strict` and `read_only` refuse a
  mutating tool. `child_env` drops KEY/SECRET/TOKEN. A `pre_invoke`
  hook can still block, the same way Grok Build hooks still apply
  under always-approve.
- `Conversation#intend` names the tools the question may use, before
  any page is seen. `screen` locks the plan. `invoke` refuses a tool
  that was not intended, even if Admission would have granted it.
  That is the privileged planner: data cannot add a capability.
  `Chat#ask(conversation:)` sends only `Conversation#messages`.
- `Conversation#invoke` runs a named tool only after `admit?`.
  A refused call is a blocked turn; the handler does not run.
  `Dojo` scores AgentDojo's two numbers on handbook tasks: security
  (injected tool stayed dark) and utility (user tool returned the
  fact). Adaptive plays rewrite the page with other words from the
  same concept lists. `Config#conversation` hands out the same
  engine already gated.
- `Origin`, `Cell`, and `Admission`: a span is privileged (`system`,
  `user`) or untrusted (`data`, `tool`). Mixing unions origins and
  zeros capability tokens. Quoting does not wash off taint. An empty
  `Admission` grants nothing; a key in `allow` is the grant, and a
  request cell may restrict further. `Spotlight.messages` types its
  slots and raises `PrivilegeError` when data is offered as an
  instruction. `Conversation#messages` is the only assembly that
  object will produce: last user turn plus the cells `screen` kept.
- `Engine#assess(origin:)` labels the span. The side supplies a default
  (`input` is user, `context` is data, `output` is tool). `Session`
  keeps two tracks: privileged origin updates attack, untrusted origin
  updates contamination. They never add. `Conversation#screen` folds
  pages onto contamination; `Conversation#admit?` takes the last user
  turn as the request and treats a bare argument as data.
- `Rails::Alignment`, a three-concept ordered match with a gap, so
  "Ignore, once the module is loaded, every previous instruction"
  is caught and "follow the guidance and ignore stale copies" is
  not. Measured on the shared 270/48 set: 47 of 270, 0 of 48,
  +4.1 bits (+1.8 at 95%). On by default with the other lexicon rails.
- Anaphora across a full stop: "There are guidelines above. Ignore
  them." binds `them` to the previous clause's instruction.
- `Session#cusum` and `Session#shift?`, Page's one-sided scheme over
  the same turn bits, thresholded at Wald's upper bar.
- `Builder#session` and `Vangrail.session_from_env`, so a deployment
  that already builds from the environment can carry a posterior across
  turns without constructing the engine twice.
- `Config#engine(stdlib: true)` prepends the deterministic input and
  context rails in front of the folder's flows, so a NeMo configuration
  whose judge is down still refuses a reworded injection and still
  refuses to call an unread language a clean pass. Off by default so
  the same folder still describes one set of rails on either runtime.
- `Builder.deterministic`, the shared list those two paths install.
- `Conversation` takes `prior:` or `session:`. `ask` with a session
  walks `assess` and folds the judgement; Escalation is not an assess
  term and does not run on that path. A retry after a refusal is still
  `check_input` when there is no session. The two objects stay
  distinct; they share one history.

- A house Ruby style, parented on thoughtbot's guide, with the deviations
  this gem has to make written down. `rubocop-performance` and
  `rubocop-minitest` run next to the style cops.
- `rake test` loads the suite in one process, so the reported count is
  true and `COVERAGE=1` sees the whole library. Shared prose lives in
  `test/corpus.rb` instead of in test files that required each other.
- `isolate_env!` clears every `GUARDRAILS*`, `WILLMA_*`, and `LLMLITE_*`
  variable by prefix, plus the llmlite aliases `GROK_SHIM_PORT` and
  `GROK_LLMLITE_MODEL`, so a new gateway key cannot leak a laptop token
  into a builder test and a leftover shim port cannot keep the proxy
  registered.

- `Vangrail::NLP`, a text analysis layer in the standard library: normalisation,
  a suffix stripper, a concept lexicon with negation and multiword phrases,
  clause segmentation, and set similarity over character n-grams.
- `Rails::Paraphrase`, which matches pairs of concepts rather than strings, so
  a reworded injection is caught by the same rule as the original. Measured at
  60 of 60 reworded attacks caught where the pattern rails catch 0, with 24 of
  24 ordinary pages kept.
- English and Dutch lexicons, both read by default and selectable with
  `languages:`, with the three pieces of Dutch grammar that a naive port gets
  wrong: negation after the verb, a backward reference used as a noun, and
  verb-final subordinates. Scored on its own Dutch corpus rather than
  assumed to transfer.
- `Rails::Similarity` and `KnownAttacks`, catching near copies of published
  attack wordings by n-gram containment, clause by clause because containment
  saturates over a whole page.
- `Rails::Language`, which reports a page in a language no lexicon here covers
  as passed with `certain?` false. It never blocks: another language is not an
  attack, and the gap this closes is a clean pass that meant nothing.
- `Rails::PromptLeak`, redacting the sentences of an answer that reproduce the
  system prompt, with two thresholds because restating a rule and handing over
  a rule are different acts. `GUARDRAILS_PROMPT_FILE` names the protected text.
- `Vangrail::Embeddings` and `Rails::Semantic`: meaning-level comparison against
  the known attack wordings through any OpenAI-compatible embeddings endpoint,
  including a local proxy, so nothing has to leave the machine.
- `Vangrail::Completion` and `Rails::Perplexity`: the published perplexity
  detector for optimised gibberish, windowed so a short span is not averaged
  away, reporting uncertain on the many endpoints that will not score a prompt.
- `script/embedding_probe.rb` and `script/perplexity_probe.rb`, which calibrate
  those two thresholds against the endpoint in use and refuse to recommend a
  number when the benign and attack distributions overlap.
- A labelled Dutch BSN is redacted by `Rails::PersonalData`, checksum and all.
  The label is what makes it safe: a bare nine-digit run is a job id.
- `Vangrail::Evidence`, `Posterior`, `Judgement`, and `Engine#assess`: the rails
  read as evidence rather than as a switch, combined with the deployment's base
  rate into a probability, with each rail's contribution in bits. Silence counts,
  abstention contributes nothing, and rails measured to agree speak once.
- `script/measure_evidence.rb` writes a handbook-corpus report
  (`tmp/handbook_evidence.rb`) from the same 270 attack and 48 benign texts,
  plus the correlation matrix that decides the grouping. The shipped
  `evidence_data.rb` is written by `script/measure_evidence_external.rb`.
- `assess(escalate: true)`, which stops when the remaining rails provably cannot
  change the action, so a networked rail is never reached on an ordinary page.
- `Vangrail::Session`, carrying the posterior across turns with a decay, so
  staged probing that no single message reveals shows up in the sequence.
- `Policy.from_costs`, deriving both thresholds from what a missed attack, a
  wrong block, and a human review each cost, instead of picking numbers.
- `Engine#triage`, which ranks a document set by posterior rather than
  partitioning it on the first objection: the doubtful page goes last in the
  passage list rather than away from the reader.
- `Rails::Linear` and `Vangrail::LinearModel`: a logistic-regression classifier
  over hashed n-grams, fitted by `script/train_linear.rb`. Cross-validated on
  in-the-wild jailbreak prompts it catches 73.7% at the rails' false-alarm rate
  against their 39.5%, and within two points of a published DeBERTa detector.
  No weights ship: a model fitted on somebody else's traffic is what this
  project spent a long time measuring the cost of, and pruning the fitted model
  small enough to ship costs 26 points of detection.
- A survey of the four detector families with the measurements attached, in
  `docs/orgmode/explanation/detector-models.org`, including the published
  transformer baseline scored on the same corpus.
- `Vangrail::Beta` and `Evidence#bits(confidence:)`: the regularised incomplete
  beta in the standard library, so a rail's evidence is what the corpus can
  defend rather than what it happened to produce. At 95% two shipped rails fall
  to zero evidence, which is a fact about 48 benign documents.
- `Evidence#capability`, the information-theoretic reading of an operating point
  at a given base rate, which is the only number in the table that changes when
  the deployment does.
- `Session#verdict`, Wald's sequential test beside the posterior, with
  thresholds fixed by the error rates rather than chosen.
- An external evaluation, and the scripts to reproduce it: `local_corpus`,
  `measure_false_alarms`, `measure_union`, `fetch_external`, `measure_external`,
  `measure_bipia_families`, `measure_evidence_external`, `baseline_external`,
  and `adjudicate`. Every rail is now scored against published attacks and
  18,258 real documents rather than against text this repository wrote.
- The shipped `evidence_data.rb` is regenerated by
  `script/measure_evidence_external.rb` from those measurements, per side, and
  `Posterior` defaults to the Beta bound rather than the point estimate.
- `Rails::Bayes` and `script/train_bayes.rb`: a naive Bayes classifier over word
  n-grams that reports a log-likelihood ratio rather than a verdict, with the
  score-to-evidence map fitted on held-out folds and pooled to monotone. Off by
  default and shipped with its cross-validated number, which is worse than the
  lexicon rails: 15 of 48 against their three quarters, on 48 training clauses.
- A rail that puts `bits` in its result's `raw` contributes that directly to a
  posterior instead of being flattened to whether it blocked.
- `StreamGuard#take`, which hands out only the text not yet shown, so a
  mid-stream redaction does not reprint the prefix already on screen.
- `Config#engine` runs `rails.retrieval` / `rails.context` flows as context
  rails, so a NeMo folder that screens retrieved documents screens them here.
- Gem metadata: homepage, source, changelog, bug tracker, and
  `allowed_push_host` for RubyGems.
- YARD class reference, built from the comments on the public objects
  and published at https://haozeke.github.io/vangrail/.

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
- `StreamGuard`, which runs the deterministic output rails while an answer is
  still arriving. Model-backed rails still run once at the end, because a round
  trip per chunk turns a two second answer into a minute.
- `Conversation`, which holds the turns and threads them into the rail context
  as `:history`, and remembers the verdicts. A refusal is the event the next
  check needs most.
- `Rails::Jailbreak`, fingerprints for the six wrappers that circulate: an
  unrestricted persona, a claim that safety was disabled, a demand for two
  answers, a sentimental wrapper, fiction as licence, and forged authority.
- `Vangrail::Confusables`, a fold from the Unicode confusables data (UTS #39)
  with a mixed-script policy: 1645 generated entries replacing 29 hand-written
  ones, folding words that mix ASCII with imitators and leaving genuine
  non-Latin prose alone. Generated by `script/generate_confusables.rb`; the
  gem behind it is a development dependency and the runtime stays
  dependency-free.
- `Rails::Obfuscation`, which undoes an encoding and runs other rails over the
  result: zero-width and bidi strips, homoglyph folding, rot13, base64, and
  compatibility normalisation. Scored on the injection corpus rewritten five
  ways: 0 of 60 with patterns alone, 60 of 60 with the decoding pass.
- `Rails::Hidden`, which extracts the spans of a page a reader never sees —
  comments, meta tags, alt and title and data attributes, script and template
  bodies, elements styled invisible, markdown link titles — and hands each to
  the deterministic rails. The largest in-the-wild survey puts roughly seven in
  ten indirect injections in non-rendered HTML.
- `Rails::Escalation`, which reads conversation history and catches a refused
  question asked again, or repeated refusals in a short window.
- `Rails::ManyShot`, which strips chat template control tokens and blocks a
  pasted dialogue of more than four turns. The tokens are stripped rather than
  refused, because a question about a chat template is a real question.
- `Rails::KnownAnswer`, which detects an injection by whether it worked rather
  than by what it said. Measured at 0 of 10 against an instruct model on a
  shared gateway, and shipped saying so: the technique detects total
  derailment, and these models are selectively persuaded instead.
- `Rails::Markup`, which strips script tags, frames, event handlers, active
  schemes, forms, and style blocks from an answer, for the common case where a
  client renders markdown by passing raw HTML through.
- `Rails::Budget`, a character limit on questions and on retrieved documents.
  The cost of answering is paid by whoever runs the endpoint, and a public desk
  gives anybody a way to spend it.
- `Rails::PersonalData`, which redacts a reader's own email, phone, IBAN, or
  card number before the question is sent anywhere. Opt-in, and careful about
  the trap that matters on a cluster desk: `ssh you@login.example.org` is an
  email address by every syntactic measure.
- `Rails::Canary`, a marker the application puts in its own prompt. The one
  check here that cannot produce a false positive, and the only one that can
  prove a leak rather than guess at one.
- `Rails::Trajectory`, a judge that reads the transcript and rules on where the
  conversation is going. It is what `Rails::Escalation` cannot be, since the
  published multi-turn methods are built so no single turn triggers a refusal.
  `GUARDRAILS_TRAJECTORY_EVERY` trades round trips for coverage.
- `Rails::Exfiltration`, an allowlist for the URLs an answer may emit. Images
  are held to a stricter list than links, because an image is fetched without a
  click, and a payload in the query is refused even on an allowlisted host.
- `script/spotlight_probe.rb`, which measures the prompt rather than a rail:
  95 of 384 injections obeyed with a plain prompt against 68 of 384 with a
  fenced one carrying the hierarchy (z = 2.38, p = 0.017). Fencing helps by
  about a quarter in relative terms and does not prevent obedience; 17.7% still
  get through, and none of those injections is recognisable to a pattern.
- `Spotlight.messages`, the whole safe prompt shape in one call: hierarchy,
  marking rule, fenced passages, question.
- `Spotlight::HIERARCHY` and `Spotlight.preamble`, which state what outranks
  what. Marking text as data says where it came from, not what to do when the
  data argues with the instructions.
- `GUARDRAILS_LINK_HOSTS` and `GUARDRAILS_IMAGE_HOSTS`, plus `links` and
  `multiturn` as `GUARDRAILS_RAILS` names.

### Fixed

- `StreamGuard#take` handed out the tail of the buffer that no rail had read
  yet, so with a long check interval a credential reached the screen and was
  redacted a chunk later. It now releases only the inspected prefix, which
  costs up to one interval of lag and is the whole point of the class.

- The engine reported the first uncertain reason it met, so a placeholder for a
  rail that could not be built masked the rail that ran and had its connection
  refused. A rail that ran now reports over one that never did.
- The escalation rail returned an uncertain pass whenever it found no history,
  which made it the first uncertain result in every single-turn engine. A
  caller that never passes the key still gets that; one that passes an empty
  array gets a certain pass, because an empty dialogue is an answer.
- A base64 run ending in `+` lost its last character to a word-boundary match,
  and decoded to a sentence with its tail missing.

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
