#ifndef CPP_PARSING_HPP
#define CPP_PARSING_HPP

#include <cctype>
#include <cstddef>
#include <iostream>
#include <memory>
#include <unordered_set>

#include <ostream>
#include <string>
#include <vector>

#include <algorithm>
#include <functional>
#include <string>
#include <unordered_map>

#include <fstream>
#include <sstream>

#include "sbpt_generated_includes.hpp"

namespace cpp_parsing {

inline ConsoleLogger logger("cpp_parsing");

const std::unordered_set<std::string> cpp_built_in_types = {
    "bool", "char", "double", "float", "long", "short", "int", "void",
};

const std::unordered_set<std::string> access_specifiers = {"public", "protected", "private"};

const std::vector<std::string> overloadable_operators = {
    // arithmetic
    "operator+",
    "operator-",
    "operator*",
    "operator/",
    "operator%",
    "operator++", // prefix/postfix
    "operator--", // prefix/postfix

    // compound assignment
    "operator+=",
    "operator-=",
    "operator*=",
    "operator/=",
    "operator%=",

    // bitwise
    "operator&",
    "operator|",
    "operator^",
    "operator~",
    "operator<<",
    "operator>>",

    // compound bitwise assignment
    "operator&=",
    "operator|=",
    "operator^=",
    "operator<<=",
    "operator>>=",

    // comparison
    "operator==",
    "operator!=",
    "operator<",
    "operator<=",
    "operator>",
    "operator>=",
    "operator<=>", // C++20 spaceship operator

    // logical
    "operator!",
    "operator&&",
    "operator||",

    // assignment
    "operator=",

    // subscript, call, pointer-like
    "operator[]",
    "operator()",
    "operator->",
    "operator->*",
    "operator*",

    // comma
    "operator,",

    // stream i/o (commonly overloaded, non-member)
    "operator<<",
    "operator>>",

    // memory management
    "operator new",
    "operator new[]",
    "operator delete",
    "operator delete[]",

};

const std::unordered_set<std::string> cpp_keywords = {
    "alignas",      "alignof",   "and",        "and_eq",       "asm",
    "auto",         "bitand",    "bitor",      "break",        "case",
    "catch",        "char16_t",  "char32_t",   "class",        "compl",
    "const",        "constexpr", "const_cast", "continue",     "decltype",
    "default",      "delete",    "do",         "dynamic_cast", "else",
    "enum",         "explicit",  "export",     "extern",       "false",
    "for",          "friend",    "goto",       "if",           "inline",
    "mutable",      "namespace", "new",        "noexcept",     "not",
    "not_eq",       "nullptr",   "operator",   "or",           "or_eq",
    "private",      "protected", "public",     "register",     "reinterpret_cast",
    "return",       "signed",    "sizeof",     "static",       "static_assert",
    "static_cast",  "struct",    "switch",     "template",     "this",
    "thread_local", "throw",     "true",       "try",          "typedef",
    "typeid",       "typename",  "union",      "unsigned",     "using",
    "virtual",      "volatile",  "wchar_t",    "while",        "xor",
    "xor_eq"};

struct ParseResult {
    ParseResult(bool succeeded, std::string parser_name = "", size_t start = 0, size_t end = 0, std::string match = "",
                std::vector<ParseResult> sub_results = {})
        : succeeded(succeeded), start(start), end(end), match(std::move(match)), parser_name(std::move(parser_name)),
          sub_results(std::move(sub_results)) {}

    bool succeeded;
    size_t start;
    size_t end;
    std::string match;
    std::string parser_name;
    std::vector<ParseResult> sub_results;
    std::string to_string() const {
        text_utils::MultilineStringAccumulator mla;

        std::function<void(const ParseResult &)> recurse = [&](const ParseResult &r) {
            mla.add("ParseResult {");
            mla.indent();
            mla.add("succeeded: ", (succeeded ? "true" : "false"));
            mla.add("parser_name: \"", parser_name, "\"");
            mla.add("start: ", start, ", end: ", end);
            mla.add("match: \"", match, "\"");

            if (!sub_results.empty()) {
                mla.add("sub_results: [");
                mla.indent();
                for (const auto &sub : sub_results) {
                    recurse(sub);
                }
                mla.unindent();
                mla.add("]");
            }

            mla.unindent();
            mla.add("}");
        };

        recurse(*this);
        return mla.str();
    }
};

std::ostream &print_parse_result(std::ostream &os, const ParseResult &result, int indent = 0);
std::ostream &operator<<(std::ostream &os, const ParseResult &result);

class CharParser {
  public:
    explicit CharParser(std::string name = "") : name(std::move(name)) {}

    virtual ParseResult parse(const std::string &input, size_t start) const = 0;

    virtual ~CharParser() = default;

    std::string name;
};

using CharParserPtr = std::shared_ptr<CharParser>;

class OptionalParser : public CharParser {
  public:
    explicit OptionalParser(std::shared_ptr<CharParser> inner, const std::string &name = "optional")
        : CharParser(name), inner_parser(std::move(inner)) {}

    ParseResult parse(const std::string &input, size_t start) const override {
        logger.debug("{} parser started", name);
        auto result = inner_parser->parse(input, start);

        if (result.succeeded) {
            logger.debug("{} parser: inner parser succeeded, returning {}", name, result.to_string());
            return result;
        } else {
            ParseResult result(true, name, start, start, "");
            logger.debug("OptionalParser: inner parser failed, returning original position ");
            return result;
        }
    }

  private:
    std::shared_ptr<CharParser> inner_parser;
};

class IfThenParser : public CharParser {
  public:
    IfThenParser(std::shared_ptr<CharParser> condition_parser, std::shared_ptr<CharParser> then_parser,
                 const std::string &name = "if_then")
        : CharParser(name), condition(std::move(condition_parser)), then_clause(std::move(then_parser)) {}

    ParseResult parse(const std::string &input, size_t start) const override {
        logger.debug("{} parser started", name);

        auto first_result = condition->parse(input, start);
        if (!first_result.succeeded) {
            return first_result;
        }
        logger.debug("trying then clause");

        return then_clause->parse(input, first_result.end);
    }

  private:
    std::shared_ptr<CharParser> condition;
    std::shared_ptr<CharParser> then_clause;
};

class OptionalWhitespaceParser : public CharParser {
  public:
    OptionalWhitespaceParser() : CharParser("optional_whitespace") {}

    ParseResult parse(const std::string &input, size_t start) const override {
        logger.debug("Starting OptionalWhitespaceParser at position: {} rest of str: '{}'", start, input.substr(start));

        size_t i = start;
        while (i < input.size()) {
            char c = input[i];
            if (std::isspace(static_cast<unsigned char>(c))) {
                logger.debug("  Whitespace at position {}", i);
                ++i;
            } else {
                logger.debug("  Non-whitespace at position {} we got {} instead, stopping", i, c);
                break;
            }
        }

        logger.debug("OptionalWhitespaceParser ending at position: {}", i);
        return {true, name, start, i, text_utils::get_substring(input, start, i)};
    }
};

class VariableParser : public CharParser {
  public:
    VariableParser() : CharParser("variable") {}

    ParseResult parse(const std::string &input, size_t start) const override {
        size_t i = start;
        logger.debug("Entering parse_variable_name at position {} remaining text: {}", i, input.substr(i));

        if (i >= input.size()) {
            logger.debug("  Empty input or out of bounds");
            return {false, name, i, i, ""};
        }

        char first_char = input[i];
        if (!(std::isalpha(first_char) || first_char == '_')) {
            logger.debug("  First character '{}' is not a valid start of variable", first_char);
            return {false, name, i, i, ""};
        }

        ++i;
        while (i < input.size()) {
            char c = input[i];
            if (std::isalnum(c) || c == '_') {
                ++i;
            } else {
                break;
            }
        }

        std::string var_name = input.substr(start, i - start);
        logger.debug("  Parsed variable name: '{}'", var_name);

        bool is_cpp_keyword = cpp_keywords.count(var_name) > 0 or cpp_built_in_types.count(var_name) > 0;
        if (is_cpp_keyword) {
            logger.debug("  Rejected: '{}' is a C++ keyword", var_name);
            return {false, name, i, i, ""};
        }

        return {true, name, start, i, text_utils::get_substring(input, start, i)};
    }
};

class TypeParser : public CharParser {
  public:
    TypeParser() : CharParser("type") {}
    ParseResult parse(const std::string &input, size_t start) const override {
        return parse_type_internal(input, start, 0);
    }

  private:
    bool is_valid_char(char c) const { return std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == ':'; }

    ParseResult parse_type_internal(const std::string &input, size_t start, int depth) const {
        size_t i = start;
        logger.debug("Entering parse_type at position {} with depth {} : {}", i, depth, input.substr(i));

        while (i < input.size()) {
            char c = input[i];
            logger.debug("  At position {}, char = '{}'", i, c);

            if (is_valid_char(c)) {
                logger.debug("    Valid char, continue");
                ++i;
            } else if (c == '<') {
                logger.debug("    Found '<', parsing type argument list...");
                ++i; // consume '<'

                while (i < input.size()) {
                    // Parse a type argument recursively
                    auto inner_result = parse_type_internal(input, i, depth + 1);
                    if (!inner_result.succeeded) {
                        logger.debug("    Failed to parse inner type at position {}", i);
                        return {false, name, i, i, ""};
                    }

                    i = inner_result.end;
                    logger.debug("    Parsed type argument up to position ", i);

                    if (i >= input.size()) {
                        logger.debug("    Unexpected end of input after type argument");
                        return {false, name, i, i, ""};
                    }

                    if (input[i] == ',') {
                        if (input[i] == ',') {
                            logger.debug("    Found ',', continuing to next type argument");
                            ++i; // consume ','

                            // Skip whitespace after comma
                            while (i < input.size() && std::isspace(static_cast<unsigned char>(input[i]))) {
                                ++i;
                            }

                            continue;
                        }
                    } else if (input[i] == '>') {
                        logger.debug("    Found matching '>' at position {}", i);
                        ++i; // consume '>'
                        if (depth == 0) {
                            return {true, name, start, i, text_utils::get_substring(input, start, i)};
                        } else {
                            return {true, name, start, i, text_utils::get_substring(input, start, i)};
                        }
                    } else {
                        logger.debug("    Unexpected character '{}' while parsing type argument list ", input[i]);
                        return {false, name, i, i, ""};
                    }
                }

                logger.debug("    Reached end of input while parsing type arguments");
                return {false, name, i, i, ""};
            } else if (c == '>') {
                if (depth == 0) {
                    logger.debug("    Found '>' at depth 0, stopping parse here at position {}", i);
                    return {true, name, start, i, text_utils::get_substring(input, start, i)};
                } else {
                    logger.debug("    Found '>' at depth {} ", depth);
                    return {true, name, start, i, text_utils::get_substring(input, start, i)};
                }
            } else if (c == ',') {
                if (depth == 0) {
                    logger.debug("    Found ',' at depth 0, treating as end of type");
                    break;
                } else {
                    logger.debug("    Found ',' at depth {}, returning to caller", depth);
                    break;
                }
            } else {
                logger.debug("    Invalid character, breaking");
                break;
            }
        }

        std::string type = input.substr(start, i - start);
        logger.debug("  Parsed type: '{}'", type);

        if (cpp_keywords.count(type)) {
            logger.debug("  Rejected: '{}' is a c++ keyword", type);
            return {false, name, start, start, ""};
        }

        logger.debug("Exiting parse_type at position {} with depth {}", i, depth);
        return {true, name, start, i, text_utils::get_substring(input, start, i)};
    }
};

class TypeQualifierSequenceParser : public CharParser {
  public:
    TypeQualifierSequenceParser() : CharParser("type_qualifier_sequence") {};
    ParseResult parse(const std::string &input, size_t start) const override {
        static const std::unordered_set<std::string> qualifiers = {"const",     "volatile",  "static",   "extern",
                                                                   "mutable",   "register",  "inline",   "thread_local",
                                                                   "constexpr", "consteval", "constinit"};

        logger.debug("Starting TypeQualifierParser at position {}", start);

        size_t i = start;
        std::vector<std::string> found_qualifiers;

        while (i < input.size()) {
            // Skip leading whitespace
            size_t whitespace_start = i;
            while (i < input.size() && std::isspace(input[i]))
                ++i;
            if (i >= input.size())
                break;

            // Peek at next word without consuming
            size_t word_start = i;
            while (i < input.size() && std::isalpha(input[i]))
                ++i;
            std::string word = input.substr(word_start, i - word_start);

            if (word.empty())
                break;

            logger.debug("  Found word: {}", word);

            if (qualifiers.count(word)) {
                found_qualifiers.push_back(word);
            } else {
                logger.debug("  Word: {} is not a qualifier. Stopping", word);
                // Reset `i` back to start of this non-qualifier word
                i = word_start;
                break;
            }
        }

        if (!found_qualifiers.empty()) {
            logger.debug("  Parsed qualifiers:");
            for (const auto &q : found_qualifiers)
                logger.debug(" {}", q);
            return {true, name, start, i, text_utils::get_substring(input, start, i)};
        }

        logger.debug("  No qualifiers found");
        return {false, name, i, i, ""};
    }
};

class LiteralParser : public CharParser {
  public:
    explicit LiteralParser(std::string literal) : CharParser("literal: " + literal), literal_(std::move(literal)) {}

    ParseResult parse(const std::string &input, size_t start) const override {
        logger.debug("Starting LiteralParser at position {}: looking for :'{}'", start, literal_);

        if (start + literal_.size() > input.size()) {

            logger.debug("  Not enough input left to match. Needed: {}, available: {}", literal_.size(),
                         (input.size() - start));

            return {false, name, start, start, ""};
        }

        std::string_view slice = std::string_view(input).substr(start, literal_.size());

        logger.debug(" Comparing {} to {}", slice, literal_);

        if (slice == literal_) {
            logger.debug("  Match succeeded. Advancing to position {}", start + literal_.size());
            auto end = start + literal_.size();
            return {true, name, start, end, text_utils::get_substring(input, start, end)};
        } else {
            logger.debug("  Match failed.");
            return {false, name, start, start, ""};
        }
    }

  private:
    std::string literal_;
};

class MatchingBraceParser : public CharParser {
  public:
    MatchingBraceParser(const std::string &name = "matching_braces") : CharParser(name) {};
    ParseResult parse(const std::string &input, size_t start) const override {

        logger.debug("Starting MatchingBraceParser at position {}", start);

        if (start >= input.size() || input[start] != '{') {
            logger.debug("  Start character is not '{{', aborting");
            return {false, name, start, start, ""};
        }

        size_t depth = 1;
        bool in_string = false;
        bool in_char = false;
        bool escape_next = false;

        for (size_t i = start + 1; i < input.size(); ++i) {
            char c = input[i];
            logger.debug("  At position {}, char = {}", i, c);

            if (escape_next) {
                logger.debug(" (escaped)");
                escape_next = false;
                continue;
            }

            if (in_string) {
                if (c == '\\') {
                    logger.debug(" (escape in string, next char escaped)");
                    escape_next = true;
                } else if (c == '"') {
                    logger.debug(" (end of string)");
                    in_string = false;
                } else {
                    logger.debug(" (inside string)\n");
                }
                continue;
            }

            if (in_char) {
                if (c == '\\') {
                    logger.debug(" (escape in char, next char escaped)");
                    escape_next = true;
                } else if (c == '\'') {
                    logger.debug(" (end of char)");
                    in_char = false;
                } else {
                    logger.debug(" (inside char)");
                }
                continue;
            }

            if (c == '"') {
                logger.debug(" (start of string)");
                in_string = true;
                continue;
            }

            if (c == '\'') {
                logger.debug(" (start of char)");
                in_char = true;
                continue;
            }

            if (c == '{') {
                ++depth;
                logger.debug(" (open brace, depth = {} )", depth);
            } else if (c == '}') {
                --depth;
                logger.debug(" (close brace, depth = {}", depth);

                if (depth == 0) {
                    size_t end = i + 1;
                    logger.debug("  Found matching closing brace at position {}", i);
                    return {true, name, start, end, text_utils::get_substring(input, start, end)};
                }
            } else {
                std::cout << "\n";
            }
        }

        logger.debug("  Matching closing brace not found");
        return {false, name, start, input.size(), text_utils::get_substring(input, start, input.size())};
    }
};

class NestedBraceParser : public CharParser {
  public:
    NestedBraceParser(CharParserPtr inner_parser, const std::string &name = "nested_brace")
        : CharParser(name), inner_parser_(std::move(inner_parser)) {}

    ParseResult parse(const std::string &input, size_t start) const override {

        logger.debug("Running NestedBraceParser starting at {}", start);

        MatchingBraceParser brace_parser;
        ParseResult outer_result = brace_parser.parse(input, start);

        if (!outer_result.succeeded) {
            logger.debug("  Outer brace parse failed");
            return {false, name, start, start, ""};
        }

        // Extract inner content (excluding outer braces)
        std::string inner_text = outer_result.match.substr(1, outer_result.match.size() - 2);
        size_t inner_start = 0;

        logger.debug("  Inner content to parse: {}", inner_text);

        ParseResult inner_result = inner_parser_->parse(inner_text, inner_start);

        if (!inner_result.succeeded) {
            logger.debug("  Inner parse failed");
            return {false, name, start, start, ""};
        }

        // Adjust inner start and end to be in terms of the original input string
        inner_result.start += outer_result.start + 1;
        inner_result.end += outer_result.start + 1;

        return {
            true,
            name,
            outer_result.start,
            outer_result.end,
            outer_result.match,
            {outer_result, inner_result} // sub-results: outer + inner
        };
    }

  private:
    CharParserPtr inner_parser_;
};

class UntilCharParser : public CharParser {
  public:
    explicit UntilCharParser(std::vector<char> target_chars, bool inclusive = true,
                             bool ignore_in_strings_and_chars = true, const std::string &name = "until_char")
        : CharParser(name), targets(std::move(target_chars)), inclusive_(inclusive),
          ignore_in_strings_and_chars_(ignore_in_strings_and_chars) {}

    ParseResult parse(const std::string &input, size_t start) const override {

        logger.debug("Starting UntilCharParser at position {} , looking for any target character {}", start,
                     (ignore_in_strings_and_chars_ ? " outside of strings and chars" : ""));

        bool in_string = false;
        bool in_char = false;
        bool escape_next = false;

        for (size_t i = start; i < input.size(); ++i) {
            char c = input[i];
            logger.debug("  At position {}, char = {}", i, c);

            if (ignore_in_strings_and_chars_) {
                if (escape_next) {
                    logger.debug(" (escaped)");
                    escape_next = false;
                    continue;
                }

                if (in_string) {
                    if (c == '\\') {
                        logger.debug(" (backslash in string, escaping next)");
                        escape_next = true;
                    } else if (c == '"') {
                        logger.debug(" (end of string)");
                        in_string = false;
                    } else {
                        logger.debug(" (inside string)");
                    }
                    continue;
                }

                if (in_char) {
                    if (c == '\\') {
                        logger.debug(" (backslash in char, escaping next)");
                        escape_next = true;
                    } else if (c == '\'') {
                        logger.debug(" (end of char)");
                        in_char = false;
                    } else {
                        logger.debug(" (inside char)");
                    }
                    continue;
                }

                if (c == '"') {
                    logger.debug(" (begin string)");
                    in_string = true;
                    continue;
                } else if (c == '\'') {
                    logger.debug(" (begin char)");
                    in_char = true;
                    continue;
                }
            }

            if (std::find(targets.begin(), targets.end(), c) != targets.end()) {
                size_t end = inclusive_ ? i + 1 : i;
                logger.debug(" (found target, stopping at position {})", end);
                return {true, name, start, end, text_utils::get_substring(input, start, end)};
            } else {
                std::cout << "\n";
            }
        }

        logger.debug("  None of the target characters found {}",
                     (ignore_in_strings_and_chars_ ? " outside of strings or chars\n" : "\n"));
        return {false, name, start, start, ""};
    }

  private:
    std::vector<char> targets;
    bool inclusive_;
    bool ignore_in_strings_and_chars_;
};

// a repeating parser attempts to repeatedly parse something until the parsing fails using the passed in parser
class RepeatingParser : public CharParser {
  public:
    explicit RepeatingParser(std::shared_ptr<CharParser> inner_parser, const std::string &name = "repeating")
        : CharParser(name), parser(std::move(inner_parser)) {}

    ParseResult parse(const std::string &input, size_t start) const override {
        size_t current = start;
        bool matched_once = false;

        logger.debug("{} repeating parser started", name);

        std::vector<ParseResult> results;

        while (true) {
            logger.debug("0");
            auto result = parser->parse(input, current);
            logger.debug("1");
            if (!result.succeeded) {
                logger.debug("2");
                break;
            }
            results.push_back(result);
            logger.debug("3");
            if (result.end == current) {
                logger.debug("4");
                // Prevent infinite loop if parser makes no progress
                break;
            }
            logger.debug("5");
            current = result.end;
            matched_once = true;
        }
        logger.debug("6");

        if (matched_once) {
            logger.debug("7");
            return {true, name, start, current, text_utils::get_substring(input, start, current), results};
        } else {
            logger.debug("8");
            return {false, name, start, start, ""};
        }
    }

  private:
    std::shared_ptr<CharParser> parser;
};

class AnyOfParser : public CharParser {
  public:
    AnyOfParser(std::vector<std::shared_ptr<CharParser>> sub_parsers, const std::string &name = "any_of")
        : CharParser(name), parsers(std::move(sub_parsers)) {}

    ParseResult parse(const std::string &input, size_t start) const override {
        for (const auto &parser : parsers) {
            auto result = parser->parse(input, start);
            if (result.succeeded) {
                return result;
            }
        }
        return {false, name, start, start, ""};
    }

  private:
    std::vector<std::shared_ptr<CharParser>> parsers;
};

class SequenceParser : public CharParser {
  public:
    SequenceParser(std::vector<CharParserPtr> parsers, const std::string &name)
        : CharParser(name), parsers_(std::move(parsers)) {}

    ParseResult parse(const std::string &input, size_t start) const override {

        logger.debug("{} sequence parser started", name);

        logger.debug("it contains: ");
        for (const auto &parser : parsers_) {
            logger.debug("{}", parser->name);
        }

        size_t current = start;

        std::vector<ParseResult> results;

        for (const auto &parser : parsers_) {
            auto result = parser->parse(input, current);
            if (!result.succeeded) {
                logger.debug("{}: did not succeed on parser {}", name, parser->name);
                return result;
            }
            results.push_back(result);
            current = result.end;
        }
        return {true, name, start, current, text_utils::get_substring(input, start, current), results};
    }

  private:
    std::vector<CharParserPtr> parsers_;
};

// helper to create parsers easier
CharParserPtr optional_whitespace();
CharParserPtr variable();
CharParserPtr type();
CharParserPtr type_qualifier_sequence();
CharParserPtr until_char(std::vector<char> target_chars, bool inclusive = true, bool ignore_in_strings_and_chars = true,
                         const std::string &name = "");
CharParserPtr literal(const std::string &s);
CharParserPtr matching_braces(const std::string &name = "");
CharParserPtr nested_braces(CharParserPtr parser, const std::string &name = "");
CharParserPtr repeating(CharParserPtr parser, const std::string &name = "");
CharParserPtr optional(CharParserPtr parser, const std::string &name = "");
CharParserPtr if_then(std::shared_ptr<CharParser> condition_parser, std::shared_ptr<CharParser> then_parser,
                      const std::string &name = "");
CharParserPtr any_of(std::vector<CharParserPtr> parsers, const std::string &name = "");
CharParserPtr sequence(std::vector<CharParserPtr> parsers, const std::string &name = "");
// === TESTING ===

inline void test_parser(const std::string &input, const CharParserPtr &parser) {

    logger.info("Testing input: {}", input);
    auto result = parser->parse(input, 0);
    if (result.succeeded && result.end == input.size()) {
        logger.info(">> SUCCESS: matched full string");
    } else if (result.succeeded) {
        logger.info(">> PARTIAL MATCH: stopped at {}", result.end);
    } else {
        logger.info(">> FAILURE: no match");
    }
}

inline std::vector<CharParserPtr> whitespace_between(const std::vector<CharParserPtr> &base_parsers) {
    std::vector<CharParserPtr> result;
    result.reserve(base_parsers.size() * 2 + 1); // start+end whitespace plus between each

    result.push_back(optional_whitespace()); // start

    for (size_t i = 0; i < base_parsers.size(); ++i) {
        result.push_back(base_parsers[i]);
        result.push_back(optional_whitespace()); // between and after
    }

    return result;
}

std::string remove_comments_from_file(const std::string &filename);

std::unordered_map<std::string, std::vector<std::string>>
collect_matches_by_parser_name(const ParseResult &result, const std::vector<std::string> &target_names);

inline CharParserPtr assignment_parser = sequence(
    whitespace_between({optional(type_qualifier_sequence()), type(), variable(), literal("="), until_char({';'})}),
    "assignment");
// assignment_parser->name = "assignment";
//
inline CharParserPtr system_include_parser = sequence(whitespace_between({literal("#include"), sequence({
                                                                                                   literal("<"),
                                                                                                   until_char({'>'}),
                                                                                               })}),
                                                      "system_include");

inline CharParserPtr local_include_parser =
    sequence(whitespace_between({literal("#include"), sequence({literal("\""), until_char({'"'}, true, false)})}),
             "local_include");

inline CharParserPtr default_value_for_parameter_suffix_parser =
    sequence(whitespace_between({literal("="), until_char({',', ')'}, false)}), "default_value_for_parameter_suffix");

inline CharParserPtr type_with_optional_reference =
    sequence({type(), optional(literal(" &"))}, "type_with_optional_reference");

inline CharParserPtr parameter_parser =
    sequence(whitespace_between({optional(type_qualifier_sequence()), type_with_optional_reference, variable(),
                                 optional(default_value_for_parameter_suffix_parser)}),
             "parameter");
// parameter_parser->name = "parameter";

inline CharParserPtr optional_parameter_sequence =
    optional(repeating(sequence({literal(","), parameter_parser})), "optional_parameter_sequence");
inline CharParserPtr optional_parameters =
    optional(if_then(parameter_parser, optional_parameter_sequence), "optional_parameters");

inline CharParserPtr parameter_tuple_parser =
    sequence(whitespace_between({literal("("), optional_parameters, literal(")")}), "parameter_tuple");
//   parameter_tuple_parser->name = "parameter_tuple";

inline std::vector<CharParserPtr> make_operator_literals() {
    std::vector<CharParserPtr> result;
    result.reserve(overloadable_operators.size());
    for (auto &op : overloadable_operators) {
        result.push_back(literal(op));
    }
    return result;
}

inline std::vector<CharParserPtr> operator_literals = make_operator_literals();

inline CharParserPtr base_function_signature_parser = sequence(whitespace_between({
                                                                   type_with_optional_reference,
                                                                   any_of({variable(), any_of(operator_literals)}),
                                                               }),
                                                               "base_function_signature");

inline CharParserPtr function_signature_parser =
    sequence(whitespace_between({base_function_signature_parser, parameter_tuple_parser}));
//   function_parser->name = "function";

inline CharParserPtr function_def_parser = sequence(whitespace_between({parameter_tuple_parser, matching_braces()}));
//   function_def_parser->name = "function_def";

inline const std::vector<CharParserPtr> access_specifier_parsers = [] {
    std::vector<CharParserPtr> result;
    result.reserve(access_specifiers.size());
    for (const auto &as : access_specifiers) {
        result.push_back(literal(as));
    }
    return result;
}();

inline const CharParserPtr access_specifier_parser = any_of(access_specifier_parsers, "access_specifier");

inline const CharParserPtr class_inheritance_parser =
    sequence(whitespace_between({literal(":"), access_specifier_parser, variable()}), "class_inheritance");

inline CharParserPtr class_def_parser =
    sequence(whitespace_between(
                 {literal("class"), variable(), optional(class_inheritance_parser), matching_braces(), literal(";")}),
             "class_def");

inline CharParserPtr using_statement_parser = sequence(
    {
        literal("using"),
        variable(),
        literal("="),
        type(),
        literal(";"),
    },
    "using_statement");

inline CharParserPtr struct_def_parser =
    sequence(whitespace_between({literal("struct"), variable(), matching_braces(), literal(";")}), "struct_def");

inline CharParserPtr source_file_body_parser = repeating(
    any_of({function_def_parser, assignment_parser, class_def_parser, struct_def_parser, using_statement_parser}),
    "source_file_body");

inline CharParserPtr source_file_namespace_body_parser =
    sequence(whitespace_between({literal("namespace"), variable(), nested_braces(source_file_body_parser)}),
             "source_file_namespace_body");

inline CharParserPtr source_file_header_parser =
    repeating(any_of({local_include_parser, system_include_parser}), "source_file_header");

inline CharParserPtr source_file_parser = sequence(
    {optional(source_file_header_parser), any_of({source_file_namespace_body_parser, source_file_body_parser})},
    "source_file");

std::vector<std::string> extract_top_level_functions(const std::string &source_code_path);

inline void test() {
    test_parser("std::unordered_map<std::string, std::vector<std::string>>", type());
    test_parser(" int x ", parameter_parser);
    test_parser("  (int x, int y) ", parameter_tuple_parser);
    test_parser("  int add(int x, int y) ", function_signature_parser);
    test_parser("  int add(int x, int y) { return x + y; } ", function_def_parser);
    test_parser("  std::optional<int> opt_mul(int x, int y) ", function_signature_parser);

    test_parser("  int x = 5;", assignment_parser);
    test_parser("  std::vector<int> x = 5;", assignment_parser);
    test_parser("  std::vector<std::vector<std::string>> x = 6;",
                assignment_parser); // success

    test_parser("std::unordered_map<std::string, std::vector<std::string>> collect_matches_by_parser_name(const "
                "ParseResult &result, const std::vector<std::string> &target_names) ",
                function_signature_parser); // success

    test_parser("  std::vector<std::vector<std::string>> x = \"test;test\";", assignment_parser);
    test_parser("  _private = count123", assignment_parser);
    test_parser("  CONST_THING = variable_123", assignment_parser);
    test_parser("  foo = bar", assignment_parser);
    test_parser("foo=123", assignment_parser);     // 123 is not a variable
    test_parser("int = value", assignment_parser); // "int" is a keyword -> reject
    test_parser(" _var = _x2", assignment_parser);
    test_parser("foo bar", assignment_parser); // fail (missing '=')

    // try {
    //     std::string commentless_code = remove_comments_from_file("main.cpp");
    //     std::string flattened = text_utils::remove_newlines(commentless_code);
    //     flattened = text_utils::collapse_whitespace(flattened);
    //     std::cout << flattened << std::endl;
    //
    //     test_parser(flattened, source_file_parser);
    //
    //     ParseResult root = source_file_parser->parse(flattened, 0);
    //     std::vector<std::string> target_parsers = {function_def_parser->name, assignment_parser->name,
    //                                                struct_def_parser->name, class_def_parser->name};
    //     auto match_map = collect_matches_by_parser_name(root, target_parsers);
    //
    //     for (const auto &[name, matches] : match_map) {
    //         std::cout << "Matches for parser: " << name << "\n";
    //         for (const auto &match : matches) {
    //             std::cout << "  - " << match << "\n";
    //         }
    //     }
    //
    // } catch (const std::exception &e) {
    //     std::cerr << "Error: " << e.what() << '\n';
    //     return 1;
    // }
    //
    // return 0;
    // }
}

} // namespace cpp_parsing

#endif
