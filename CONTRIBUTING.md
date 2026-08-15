# Contributing

The suite is stdlib minitest. There is no bundle.

```bash
gem install minitest
rake test
ruby -Ilib test/test_engine.rb
```

Style is [thoughtbot's Ruby guide](https://github.com/thoughtbot/guides/tree/main/ruby),
with the deviations this gem has to make written down in
[`docs/orgmode/contributing/style.org`](docs/orgmode/contributing/style.org).

```bash
gem install rubocop rubocop-performance rubocop-minitest
rubocop
```

How the suite is run, and why files must not require each other:
[`docs/orgmode/contributing/testing.org`](docs/orgmode/contributing/testing.org).
The rest of the contributing notes live in
[`docs/orgmode/contributing/index.org`](docs/orgmode/contributing/index.org).
