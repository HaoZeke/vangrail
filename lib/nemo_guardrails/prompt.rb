# frozen_string_literal: true

module NemoGuardrails
  # The slice of Jinja that guardrail prompts actually use.
  #
  # NeMo prompt files address the turn through `{{ user_input }}` and
  # `{{ bot_response }}`, occasionally with a `{% if %}` around an optional
  # section. Rendering that needs variable substitution and one conditional, not
  # a template engine, and a guardrail prompt is the last place to want
  # arbitrary evaluation: the text being substituted is attacker-influenced by
  # construction.
  #
  # Supported, and nothing else:
  #
  #   {{ name }}                    substitute, HTML untouched
  #   {{ name | upper }}            upper, lower, trim
  #   {% if name %} ... {% endif %} include when truthy and non-empty
  #
  # An unknown variable renders empty. An unknown filter or tag raises, because
  # a prompt that silently drops the rule you wrote is worse than one that fails
  # to load.
  module Prompt
    FILTERS = {
      'upper' => ->(s) { s.upcase },
      'lower' => ->(s) { s.downcase },
      'trim' => ->(s) { s.strip }
    }.freeze

    TAG = /\{%\s*(\w+)\s*([^%]*?)\s*%\}/
    VAR = /\{\{\s*([\w.]+)\s*(?:\|\s*(\w+)\s*)?\}\}/

    module_function

    def render(template, vars = {})
      text = conditionals(template.to_s, vars)
      text.gsub(VAR) do
        name = Regexp.last_match(1)
        filter = Regexp.last_match(2)
        apply(filter, lookup(vars, name))
      end
    end

    # Only `{% if x %}...{% endif %}`, innermost first so nesting resolves.
    def conditionals(text, vars)
      out = text
      loop do
        replaced = out.sub(/\{%\s*if\s+([\w.]+)\s*%\}(.*?)\{%\s*endif\s*%\}/m) do
          truthy?(lookup(vars, Regexp.last_match(1))) ? Regexp.last_match(2) : ''
        end
        break out if replaced == out

        out = replaced
      end
      check_tags(out)
    end

    def check_tags(text)
      text.scan(TAG) do |tag, _rest|
        raise ArgumentError, "unsupported template tag {% #{tag} %}" unless tag == 'raw'
      end
      text
    end

    def lookup(vars, name)
      name.split('.').reduce(vars) do |acc, part|
        break nil unless acc.respond_to?(:[])

        acc[part] || (acc.respond_to?(:key?) ? acc[part.to_sym] : nil)
      end
    end

    def apply(filter, value)
      text = value.to_s
      return text if filter.nil?

      fn = FILTERS[filter]
      raise ArgumentError, "unsupported template filter |#{filter}" unless fn

      fn.call(text)
    end

    def truthy?(value)
      return false if value.nil? || value == false

      !(value.respond_to?(:empty?) && value.empty?)
    end
  end
end
