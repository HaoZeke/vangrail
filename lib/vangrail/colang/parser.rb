# frozen_string_literal: true

require_relative '../errors'
require_relative 'ast'

module Vangrail
  module Colang
    # Reads the Colang 1.0 subset that rail flows are written in.
    #
    #   define flow self check input
    #     $allowed = execute self_check_input
    #     if not $allowed
    #       bot refuse to respond
    #       stop
    #
    #   define bot refuse to respond
    #     "I'm sorry, I can't respond to that."
    #
    # That subset covers the input and output rails that ship with the toolkit
    # and the ones people write. Dialog flows with user-intent matching are not
    # supported, and a file using them raises rather than loading with the
    # matching quietly missing: a guardrail that half-loads is a guardrail that
    # reports checks it is not running.
    #
    # Indentation defines blocks. Tabs are refused, because a file mixing tabs
    # and spaces would otherwise parse into a different program than it looks.
    class Parser
      Line = Struct.new(:indent, :text, :number, keyword_init: true)

      def self.parse(source, filename: nil)
        new(source, filename: filename).parse
      end

      def initialize(source, filename: nil)
        @source = source.to_s
        @filename = filename
        @flows = {}
        @bot_messages = {}
        @user_messages = {}
      end

      def parse
        lines = significant_lines
        index = 0
        index = definition(lines, index) while index < lines.length
        Program.new(flows: @flows, bot_messages: @bot_messages, user_messages: @user_messages)
      end

      private

      def significant_lines
        @source.lines.each_with_index.filter_map do |raw, i|
          number = i + 1
          raise error('tabs are not allowed in Colang indentation', number) if raw.start_with?("\t")

          text = raw.rstrip
          stripped = text.strip
          next if stripped.empty? || stripped.start_with?('#')

          Line.new(indent: text[/\A */].length, text: stripped, number: number)
        end
      end

      # One `define ...` header plus everything indented under it.
      def definition(lines, index)
        header = lines[index]
        raise error("expected a `define` block, got #{header.text.inspect}", header.number) unless
          header.text.start_with?('define ')

        body, next_index = block(lines, index + 1, header.indent)
        case header.text
        when /\Adefine (flow|subflow)\s+(.+)\z/
          name = Regexp.last_match(2).strip
          @flows[name] =
            Flow.new(name: name, body: statements(body), subflow: Regexp.last_match(1) == 'subflow')
        when /\Adefine bot\s+(.+)\z/
          @bot_messages[Regexp.last_match(1).strip] = strings(body)
        when /\Adefine user\s+(.+)\z/
          @user_messages[Regexp.last_match(1).strip] = strings(body)
        else
          raise error("unsupported definition #{header.text.inspect}", header.number)
        end
        next_index
      end

      # Every line indented deeper than `indent`, and where to resume.
      def block(lines, index, indent)
        body = []
        while index < lines.length && lines[index].indent > indent
          body << lines[index]
          index += 1
        end
        [body, index]
      end

      def statements(lines)
        result = []
        index = 0
        while index < lines.length
          statement, index = statement(lines, index)
          result << statement
        end
        result
      end

      def statement(lines, index)
        line = lines[index]
        case line.text
        when /\A\$(\w+)\s*=\s*(.+)\z/
          [Assign.new(variable: Regexp.last_match(1), expression: expression(Regexp.last_match(2), line)),
           index + 1]
        when /\Aexecute\s+(.+)\z/
          [action_call(Regexp.last_match(1), line), index + 1]
        when /\Abot\s+(.+)\z/
          [Bot.new(message: Regexp.last_match(1).strip), index + 1]
        when /\Astop\z/
          [Stop.new(reason: nil), index + 1]
        when /\Aif\s+(.+)\z/
          # $~ is frame-local, so the captured condition is passed rather than
          # read again inside the callee.
          conditional(lines, index, line, Regexp.last_match(1))
        when /\Aelse\z/
          raise error('`else` without a matching `if`', line.number)
        else
          raise error("unsupported statement #{line.text.inspect}", line.number)
        end
      end

      def conditional(lines, index, line, condition_text)
        condition = condition(condition_text, line)
        then_lines, index = block(lines, index + 1, line.indent)
        else_lines = []
        if index < lines.length && lines[index].text == 'else' && lines[index].indent == line.indent
          else_lines, index = block(lines, index + 1, lines[index].indent)
        end
        [If.new(condition: condition, then_body: statements(then_lines), else_body: statements(else_lines)),
         index]
      end

      def expression(text, line)
        return action_call(Regexp.last_match(1), line) if text =~ /\Aexecute\s+(.+)\z/
        return Literal.new(value: unquote(text)) if quoted?(text)
        return Var.new(name: Regexp.last_match(1)) if text =~ /\A\$(\w+)\z/

        raise error("unsupported expression #{text.inspect}", line.number)
      end

      def action_call(text, line)
        name, args = text.match(/\A([\w.]+)\s*(?:\((.*)\))?\s*\z/)&.captures
        raise error("unsupported action call #{text.inspect}", line.number) unless name

        Execute.new(action: name, arguments: arguments(args, line))
      end

      # key="value", key=$var, key=42. Positional arguments are refused: an
      # action here is a Ruby method taking a keyword hash.
      def arguments(text, line)
        return {} if text.nil? || text.strip.empty?

        text.split(/,(?=(?:[^"]*"[^"]*")*[^"]*\z)/).to_h do |pair|
          key, value = pair.split('=', 2).map { |s| s.to_s.strip }
          raise error("argument #{pair.inspect} needs a name", line.number) if value.nil? || key.empty?

          [key, argument_value(value, line)]
        end
      end

      def argument_value(value, line)
        return unquote(value) if quoted?(value)
        return Var.new(name: Regexp.last_match(1)) if value =~ /\A\$(\w+)\z/
        return value.to_i if value.match?(/\A-?\d+\z/)
        return true if %w[True true].include?(value)
        return false if %w[False false].include?(value)

        raise error("unsupported argument value #{value.inspect}", line.number)
      end

      def condition(text, line)
        text = text.strip
        return Not.new(expression: condition(Regexp.last_match(1), line)) if text =~ /\Anot\s+(.+)\z/
        if text =~ /\A(.+?)\s*(==|!=)\s*(.+)\z/
          return Compare.new(
            left: condition(Regexp.last_match(1), line),
            operator: Regexp.last_match(2),
            right: condition(Regexp.last_match(3), line),
          )
        end
        return Var.new(name: Regexp.last_match(1)) if text =~ /\A\$(\w+)\z/
        return Literal.new(value: unquote(text)) if quoted?(text)
        return Literal.new(value: true) if %w[True true].include?(text)
        return Literal.new(value: false) if %w[False false].include?(text)

        raise error("unsupported condition #{text.inspect}", line.number)
      end

      def strings(lines)
        lines.map do |line|
          unless quoted?(line.text)
            raise error("expected a quoted message, got #{line.text.inspect}",
                        line.number)
          end

          unquote(line.text)
        end
      end

      def quoted?(text)
        text.length >= 2 && ((text.start_with?('"') && text.end_with?('"')) ||
          (text.start_with?("'") && text.end_with?("'")))
      end

      def unquote(text)
        text[1..-2].gsub('\\"', '"').gsub("\\'", "'")
      end

      def error(message, number)
        where = [@filename, number].compact.join(':')
        ColangError.new("#{where}: #{message}")
      end
    end
  end
end
