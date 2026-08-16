# frozen_string_literal: true

require_relative 'ast'

module Vangrail
  module Colang
    # One grammar for assign RHS, `if` conditions, and action arguments.
    #
    # Strings are tokenized before `==` / `!=` is considered, so
    # `"a == b" == $x` is a compare of a literal against a variable.
    class ValueParser
      def self.parse(text, line, error)
        new(text, line, error).parse
      end

      def initialize(text, line, error)
        @text = text
        @line = line
        @error = error
      end

      def parse
        tokens = tokenize
        node, index = parse_value(tokens, 0)
        raise fail_value(@text) unless tokens[index][0] == :eof

        node
      end

      private

      def tokenize
        tokens = []
        index = 0
        while index < @text.length
          if @text[index] == ' '
            index += 1
          else
            token, index = next_token(index)
            tokens << token
          end
        end
        tokens << [:eof]
        tokens
      end

      def next_token(index)
        char = @text[index]
        if char == '"' || char == "'"
          read_string(index)
        elsif char == '$' && (name = @text[(index + 1)..][/\A\w+/])
          [[:var, name], index + 1 + name.length]
        elsif @text[index, 2] == '=='
          [[:eqeq, '=='], index + 2]
        elsif @text[index, 2] == '!='
          [[:neq, '!='], index + 2]
        elsif char == '='
          [[:eq, '='], index + 1]
        elsif char == '('
          [[:lparen], index + 1]
        elsif char == ')'
          [[:rparen], index + 1]
        elsif char == ','
          [[:comma], index + 1]
        elsif (num = @text[index..][/\A-?\d+/])
          [[:int, num.to_i], index + num.length]
        elsif (word = @text[index..][/\A[\w.]+/])
          [[:ident, word], index + word.length]
        else
          raise fail_value(@text)
        end
      end

      def read_string(start)
        quote = @text[start]
        index = start + 1
        while index < @text.length
          return [[:string, unquote(@text[start..index])], index + 1] if @text[index] == quote

          index += @text[index] == '\\' && index + 1 < @text.length ? 2 : 1
        end
        raise @error.call("unterminated string in #{@text.inspect}", @line.number)
      end

      def parse_value(tokens, index)
        tok = tokens[index]
        if tok[0] == :ident && tok[1] == 'not'
          expr, index = parse_value(tokens, index + 1)
          return [Not.new(expression: expr), index]
        end

        left, index = parse_atom(tokens, index)
        op = tokens[index]
        return [left, index] unless %i[eqeq neq].include?(op[0])

        right, index = parse_value(tokens, index + 1)
        [Compare.new(left: left, operator: op[1], right: right), index]
      end

      def parse_atom(tokens, index)
        tok = tokens[index]
        case tok[0]
        when :string then [Literal.new(value: tok[1]), index + 1]
        when :int then [Literal.new(value: tok[1]), index + 1]
        when :var then [Var.new(name: tok[1]), index + 1]
        when :ident
          word = tok[1]
          return parse_execute(tokens, index + 1) if word == 'execute'
          return [Literal.new(value: true), index + 1] if %w[True true].include?(word)
          return [Literal.new(value: false), index + 1] if %w[False false].include?(word)

          raise fail_value(word)
        else
          raise fail_value(tok)
        end
      end

      # execute name / execute name(key=value, ...). Positional arguments
      # are refused: an action here is a Ruby method taking a keyword hash.
      def parse_execute(tokens, index)
        name_tok = tokens[index]
        raise fail_value(name_tok) unless name_tok[0] == :ident

        name = name_tok[1]
        index += 1
        return [Execute.new(action: name, arguments: {}), index] unless tokens[index][0] == :lparen

        args, index = parse_arguments(tokens, index + 1)
        [Execute.new(action: name, arguments: args), index]
      end

      def parse_arguments(tokens, index)
        return [{}, index + 1] if tokens[index][0] == :rparen

        args = {}
        loop do
          key = tokens[index]
          unless key[0] == :ident && tokens[index + 1][0] == :eq
            raise @error.call("argument #{key[1].inspect} needs a name", @line.number)
          end

          val, index = parse_value(tokens, index + 2)
          args[key[1]] = val
          case tokens[index][0]
          when :comma then index += 1
          when :rparen then return [args, index + 1]
          else raise fail_value(@text)
          end
        end
      end

      def unquote(text)
        text[1..-2].gsub('\\"', '"').gsub("\\'", "'")
      end

      def fail_value(what)
        @error.call("unsupported value #{what.inspect}", @line.number)
      end
    end
  end
end
