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

inline Logger logger("cpp_parsing");

const std::unordered_set<std::string> cpp_built_in_types = {
    "bool", "char", "double", "float", "long", "short", "int", "void",
};

const std::vector<std::string> cpp_sign_specifier = {"unsigned", "signed"};
const std::vector<std::string> cpp_size_specifier = {"short", "long", "long long"};

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

inline std::string truncate(const std::string &s, int cutoff = 50) {
    return text_utils::get_substring(s, 0, cutoff) + "...";
}

inline std::string get_next_part_of_string(const std::string &input, int start, int lookahead = 50) {
    return text_utils::get_substring(input, start, start + lookahead) + "...";
}

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
            mla.add("succeeded: ", (r.succeeded ? "true" : "false"));
            mla.add("parser_name: \"", r.parser_name, "\"");
            mla.add("start: ", r.start, ", end: ", r.end);
            mla.add("match: \"", r.match, "\"");

            if (!r.sub_results.empty()) {
                mla.add("sub_results: [");
                mla.indent();
                for (const auto &sub : r.sub_results) {
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

ParseResult clean_parse_result(const ParseResult &r);

const cpp_parsing::ParseResult *find_first_by_name(const cpp_parsing::ParseResult *root, const std::string &target);

// Find any node whose parser_name contains substring `substr`. Example: "type_with_optional_reference".
const cpp_parsing::ParseResult *find_first_name_contains(const cpp_parsing::ParseResult *root,
                                                         const std::string &substr);

// Collect all nodes with parser_name == target (DFS)
void collect_by_name(const cpp_parsing::ParseResult *root, const std::string &target,
                     std::vector<const cpp_parsing::ParseResult *> &out);

ParseResult parse_source_or_header_file(const std::string &source_code_path);

std::vector<std::pair<std::string, std::string>> bfs_collect_matches(const cpp_parsing::ParseResult *root,
                                                                     const std::vector<std::string> &names);

std::string node_text(const cpp_parsing::ParseResult *node);

// deprecated for the to_string funciton remove soon.
std::ostream &print_parse_result(std::ostream &os, const ParseResult &result, int indent = 0);
std::ostream &operator<<(std::ostream &os, const ParseResult &result);

class CharParser {
  public:
    explicit CharParser(std::string name = "") : name(std::move(name)) {}

    virtual ParseResult parse(const std::string &input, size_t start = 0) const = 0;

    virtual ~CharParser() = default;

    std::string name;
};

using CharParserPtr = std::shared_ptr<CharParser>;

// helper to create parsers easier
CharParserPtr optional_whitespace();
CharParserPtr identifier();
CharParserPtr variable();
CharParserPtr base_type();
CharParserPtr type_qualifier_sequence();
CharParserPtr until_char(std::vector<char> target_chars, bool inclusive = true, bool ignore_in_strings_and_chars = true,
                         const std::string &name = "");

CharParserPtr literal(const std::string &s);

inline std::vector<CharParserPtr> create_literal_parsers(std::vector<std::string> literals) {
    std::vector<CharParserPtr> ls;
    for (const auto &l : literals) {
        auto lp = literal(l);
        ls.push_back(lp);
    }
    return ls;
}

CharParserPtr matching_string_pair(const std::string &name = "matching_braces", std::string left = "{",
                                   std::string right = "}");
CharParserPtr nested_string_pair(CharParserPtr parser, const std::string &name = "nested_braces",
                                 std::string left = "{", std::string right = "}");
CharParserPtr repeating(CharParserPtr parser, const std::string &name = "repeating");
CharParserPtr optional(CharParserPtr parser, const std::string &name = "optional");
CharParserPtr deferred();
CharParserPtr if_then(std::shared_ptr<CharParser> condition_parser, std::shared_ptr<CharParser> then_parser,
                      const std::string &name = "if_then");
CharParserPtr any_of(std::vector<CharParserPtr> parsers, const std::string &name = "any_of");
CharParserPtr sequence(std::vector<CharParserPtr> parsers, const std::string &name = "sequence");

inline void log_start_of_parser(const std::string &name, const std::string &input, size_t start) {
    logger.debug("at position {}, rest of text: {}", start, get_next_part_of_string(input, start));
}

class DecimalLiteralParser : public CharParser {
  public:
    explicit DecimalLiteralParser(std::string name = "decimal_literal") : CharParser(std::move(name)) {}

    ParseResult parse(const std::string &input, size_t start = 0) const override {
        size_t i = start;
        while (i < input.size() && std::isdigit(static_cast<unsigned char>(input[i]))) {
            ++i;
        }

        if (i == start) {
            // No digits consumed → fail
            return ParseResult(false, name, start, start, "");
        }

        std::string matched = input.substr(start, i - start);
        return ParseResult(true, name, start, i, matched);
    }
};

class IdentifierParser : public CharParser {
  public:
    IdentifierParser() : CharParser("identifier") {}

    ParseResult parse(const std::string &input, size_t start) const override {
        LogSection ls(logger, "{} parser", name);
        log_start_of_parser(name, input, start);

        size_t pos = start;
        const size_t len = input.size();

        if (pos >= len) {
            logger.debug("{} parser failed: start position {} beyond input length {}", name, start, len);
            return {false, name, start, start, "", {}};
        }

        char c = input[pos];
        if (!isIdentifierStartChar(c)) {
            logger.debug("{} parser failed: first char '{}' at position {} is not valid start char", name, c, pos);
            return {false, name, start, start, "", {}};
        }

        ++pos;
        while (pos < len && isIdentifierContinueChar(input[pos])) {
            ++pos;
        }

        std::string matched = input.substr(start, pos - start);
        logger.debug("{} parser succeeded: matched '{}' from {} to {}", name, matched, start, pos);

        return {true, name, start, pos, std::move(matched), {}};
    }

  private:
    static bool isIdentifierStartChar(char c) { return (std::isalpha(static_cast<unsigned char>(c)) || c == '_'); }
    static bool isIdentifierContinueChar(char c) { return (std::isalnum(static_cast<unsigned char>(c)) || c == '_'); }
};

class OptionalParser : public CharParser {
  public:
    explicit OptionalParser(std::shared_ptr<CharParser> inner, const std::string &name = "optional")
        : CharParser(name), inner_parser(std::move(inner)) {}

    ParseResult parse(const std::string &input, size_t start) const override {
        LogSection ls(logger, "{} parser", name);
        log_start_of_parser(name, input, start);

        auto result = inner_parser->parse(input, start);
        logger.debug("{} got out", name);

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
        LogSection ls(logger, "{} parser", name);
        log_start_of_parser(name, input, start);

        size_t current = start;
        std::vector<ParseResult> results;

        // Always attempt the condition
        auto first_result = condition->parse(input, current);
        results.push_back(first_result);

        if (!first_result.succeeded) {
            // Return with just the condition result
            return {false,  name, start, first_result.end, text_utils::get_substring(input, start, first_result.end),
                    results};
        }

        // If condition succeeded, always attempt then_clause
        current = first_result.end;
        auto second_result = then_clause->parse(input, current);
        results.push_back(second_result);

        return {first_result.succeeded && second_result.succeeded,          name,   start, second_result.end,
                text_utils::get_substring(input, start, second_result.end), results};
    }

  private:
    std::shared_ptr<CharParser> condition;
    std::shared_ptr<CharParser> then_clause;
};

// DeferredParser: holds a function returning a parser, the use case is so that we can define recursive parsers without
// having circular dependencies
class DeferredParser : public CharParser {
    // Mutable shared_ptr so it can be assigned later
    std::shared_ptr<CharParser> actual_parser;

  public:
    DeferredParser() : CharParser("deferred"), actual_parser(nullptr) {}

    // Setter to assign the actual parser later
    void set_parser(CharParserPtr parser) { actual_parser = std::move(parser); }

    ParseResult parse(const std::string &input, size_t start) const override {

        LogSection ls(logger, "{} parser", name);
        log_start_of_parser(name, input, start);

        if (!actual_parser) {
            throw std::runtime_error("DeferredParser: actual parser not set");
        }
        return actual_parser->parse(input, start);
    }
};

class OptionalWhitespaceParser : public CharParser {
  public:
    OptionalWhitespaceParser() : CharParser("optional_whitespace") {}

    ParseResult parse(const std::string &input, size_t start) const override {
        LogSection ls(logger, "{} parser", name);
        log_start_of_parser(name, input, start);

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

        std::string ws = input.substr(start, i - start);
        return {true, name, start, i, ws};
    }
};

class VariableParser : public CharParser {
  public:
    VariableParser() : CharParser("variable") {}

    ParseResult parse(const std::string &input, size_t start) const override {
        size_t i = start;

        LogSection ls(logger, "{} parser", name);
        log_start_of_parser(name, input, start);

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

        return {true, name, start, i, var_name};
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

        LogSection ls(logger, "{} parser", name);
        log_start_of_parser(name, input, start);

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
                        logger.debug("    Unexpected character '{}' while parsing type "
                                     "argument list ",
                                     input[i]);
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

        LogSection ls(logger, "{} parser", name);
        log_start_of_parser(name, input, start);

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

        LogSection ls(logger, "{} parser", name);
        log_start_of_parser(name, input, start);

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

class MatchingStringPairParser : public CharParser {
  public:
    MatchingStringPairParser(const std::string &name = "matching_strings", std::string left_str = "{",
                             std::string right_str = "}")
        : CharParser(name), left_str(std::move(left_str)), right_str(std::move(right_str)) {}

    std::string left_str;
    std::string right_str;

    ParseResult parse(const std::string &input, size_t start) const override {
        LogSection ls(logger, "{} parser", name);
        log_start_of_parser(name, input, start);

        if (start >= input.size() || !starts_with(input, start, left_str)) {
            logger.debug("  Start sequence is not '{}', aborting", left_str);
            return {false, name, start, start, ""};
        }

        size_t depth = 1;
        bool in_string = false;
        bool in_char = false;
        bool escape_next = false;

        size_t i = start + left_str.size();
        while (i < input.size()) {
            char c = input[i];

            if (escape_next) {
                escape_next = false;
                ++i;
                continue;
            }

            if (in_string) {
                if (c == '\\') {
                    escape_next = true;
                } else if (c == '"') {
                    in_string = false;
                }
                ++i;
                continue;
            }

            if (in_char) {
                if (c == '\\') {
                    escape_next = true;
                } else if (c == '\'') {
                    in_char = false;
                }
                ++i;
                continue;
            }

            if (c == '"') {
                in_string = true;
                ++i;
                continue;
            }

            if (c == '\'') {
                in_char = true;
                ++i;
                continue;
            }

            if (starts_with(input, i, left_str)) {
                ++depth;
                i += left_str.size();
                continue;
            }

            if (starts_with(input, i, right_str)) {
                --depth;
                i += right_str.size();
                if (depth == 0) {
                    size_t end = i;
                    logger.debug("  Found matching closing sequence at position {}", end - right_str.size());
                    return {true, name, start, end, text_utils::get_substring(input, start, end)};
                }
                continue;
            }

            ++i;
        }

        logger.debug("  Matching closing sequence not found");
        return {false, name, start, input.size(), text_utils::get_substring(input, start, input.size())};
    }

  private:
    static bool starts_with(const std::string &s, size_t pos, const std::string &prefix) {
        return s.compare(pos, prefix.size(), prefix) == 0;
    }
};

// NOTE: untested, but leaving it here for later because it's a good idea I might need in the future.
class MatchingPairParser : public CharParser {
  public:
    MatchingPairParser(CharParserPtr left_parser, CharParserPtr right_parser, const std::string &name = "matching_pair")
        : CharParser(name), left_parser_(std::move(left_parser)), right_parser_(std::move(right_parser)) {}

    ParseResult parse(const std::string &input, size_t start) const override {
        LogSection ls(logger, "{} parser", name);
        log_start_of_parser(name, input, start);

        // Parse the left delimiter
        auto left_result = left_parser_->parse(input, start);
        if (!left_result.succeeded) {
            logger.debug("  Left delimiter parse failed");
            return {false, name, start, start, ""};
        }

        size_t depth = 1;
        bool in_string = false;
        bool in_char = false;
        bool escape_next = false;
        size_t i = left_result.end;

        while (i < input.size()) {
            char c = input[i];

            if (escape_next) {
                escape_next = false;
                ++i;
                continue;
            }

            if (in_string) {
                if (c == '\\') {
                    escape_next = true;
                } else if (c == '"') {
                    in_string = false;
                }
                ++i;
                continue;
            }

            if (in_char) {
                if (c == '\\') {
                    escape_next = true;
                } else if (c == '\'') {
                    in_char = false;
                }
                ++i;
                continue;
            }

            if (c == '"') {
                in_string = true;
                ++i;
                continue;
            }

            if (c == '\'') {
                in_char = true;
                ++i;
                continue;
            }

            // Try parsing another left delimiter
            {
                auto inner_left = left_parser_->parse(input, i);
                if (inner_left.succeeded) {
                    ++depth;
                    i = inner_left.end;
                    continue;
                }
            }

            // Try parsing a right delimiter
            {
                auto inner_right = right_parser_->parse(input, i);
                if (inner_right.succeeded) {
                    --depth;
                    i = inner_right.end;
                    if (depth == 0) {
                        logger.debug("  Found matching closing delimiter at {}", i);
                        return {true,
                                name,
                                start,
                                i,
                                text_utils::get_substring(input, start, i),
                                {left_result, inner_right}};
                    }
                    continue;
                }
            }

            ++i;
        }

        logger.debug("  Matching closing delimiter not found");
        return {false, name, start, input.size(), text_utils::get_substring(input, start, input.size())};
    }

  private:
    CharParserPtr left_parser_;
    CharParserPtr right_parser_;
};

class NestedStringPairParser : public CharParser {
  public:
    NestedStringPairParser(CharParserPtr inner_parser, const std::string &name = "nested_string",
                           std::string left_str = "{", std::string right_str = "}")
        : CharParser(name), inner_parser_(std::move(inner_parser)), left_str(std::move(left_str)),
          right_str(std::move(right_str)) {}

    std::string left_str, right_str;

    ParseResult parse(const std::string &input, size_t start) const override {
        LogSection ls(logger, "{} parser", name);
        log_start_of_parser(name, input, start);

        MatchingStringPairParser match_parser(name, left_str, right_str);
        ParseResult outer_result = match_parser.parse(input, start);

        if (!outer_result.succeeded) {
            logger.debug("  Outer string parse failed");
            return {false, name, start, start, ""};
        }

        // Extract inner content excluding outer delimiters
        if (outer_result.match.size() < left_str.size() + right_str.size()) {
            logger.debug("  Match too small to contain delimiters");
            return {false, name, start, start, ""};
        }

        std::string inner_text =
            outer_result.match.substr(left_str.size(), outer_result.match.size() - left_str.size() - right_str.size());
        size_t inner_start = 0;

        logger.debug("  Inner content to parse: {}", truncate(inner_text));

        ParseResult inner_result = inner_parser_->parse(inner_text, inner_start);

        if (!inner_result.succeeded) {
            logger.debug("  Inner parse failed");
            return {false, name, start, start, ""};
        }

        // Adjust inner result's positions relative to the original input
        inner_result.start += outer_result.start + left_str.size();
        inner_result.end += outer_result.start + left_str.size();

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

        LogSection ls(logger, "{} parser", name);
        log_start_of_parser(name, input, start);

        logger.debug("Starting UntilCharParser at position {} , looking for any target "
                     "character {}",
                     start, (ignore_in_strings_and_chars_ ? " outside of strings and chars" : ""));

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

// NOTE: the next step was to create an enum parser, and then the ability to serialize that as well in the meta program.
class CommaSeparatedTupleParser : public CharParser {
  public:
    CommaSeparatedTupleParser(CharParserPtr element_parser, std::string name = "comma_separated_tuple")
        : CharParser(std::move(name)), element_parser(std::move(element_parser)) {}

    ParseResult parse(const std::string &input, size_t start = 0) const override {
        // Build the grammar dynamically:
        // ( element ( "," element )* )?
        auto comma_then_element = sequence({literal(","), element_parser}, "comma_then_element");
        auto repeating_comma_elements = repeating(comma_then_element, "repeating_comma_elements");
        auto full_sequence = optional(sequence({element_parser, repeating_comma_elements}, "tuple_core"), name);

        return full_sequence->parse(input, start);
    }

  private:
    CharParserPtr element_parser;
};

// a repeating parser attempts to repeatedly parse something until the parsing
// fails using the passed in parser
class RepeatingParser : public CharParser {
  public:
    explicit RepeatingParser(std::shared_ptr<CharParser> inner_parser, const std::string &name = "repeating")
        : CharParser(name), parser(std::move(inner_parser)) {}

    ParseResult parse(const std::string &input, size_t start) const override {
        size_t current = start;
        bool matched_once = false;

        LogSection ls(logger, "{} parser", name);
        log_start_of_parser(name, input, start);

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
        // logger.debug("{} any of parser started at position {}", name, start);

        for (const auto &parser : parsers) {
            // logger.debug("{} trying sub-parser '{}'", name, parser->name);
            auto result = parser->parse(input, start);
            if (result.succeeded) {
                // logger.debug("{} sub-parser '{}' succeeded with match '{}'", name, parser->name, result.match);
                return result;
            } else {
                // logger.debug("{} sub-parser '{}' failed", name, parser->name);
            }
        }

        // logger.debug("{} parser failed: no sub-parsers matched at position {}", name, start);
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

        LogSection ls(logger, "{} parser", name);
        log_start_of_parser(name, input, start);

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

// TODO: should this be a class? why or why not.
inline CharParserPtr comma_separated_sequence_parser(CharParserPtr element_parser) {

    CharParserPtr after_the_first_element_parser =
        optional(repeating(sequence(whitespace_between({literal(","), element_parser}),
                                    "comma_element_" + element_parser->name)),
                 "after_the_first_element_parser");

    // NOTE: we do optional here, because we allow the empty sequence to be valid
    CharParserPtr optional_element_parser = optional(
        sequence({if_then(sequence(whitespace_between({element_parser})), after_the_first_element_parser,
                          "one_or_more_element_" + element_parser->name),
                  // NOTE: that this optional here is when we do something like 1, 2, 3, and that's valid in some cases
                  optional(literal(","))}),
        "optional_elements");

    return optional_element_parser;
}

std::string remove_comments_from_file(const std::string &filename);

std::unordered_map<std::string, std::vector<std::string>>
collect_matches_by_parser_name(const ParseResult &result, const std::vector<std::string> &target_names = {});

// inline CharParserPtr template_name =

// #ifndef M_PI
// #define M_PI 3.14159265358979323846
// #endif

// TODO: to support the above we need support for until_literal
inline CharParserPtr macro_if_statement = sequence({});

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

// https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2023/n4950.pdf section 9.2.1
// NOTE: not fully implemented yet
// inline CharParserPtr declaration_specifier_sequence_parser = ;
//

inline CharParserPtr optionally_namespaced_identifier() {
    return sequence({optional(sequence({identifier(), literal("::")})), identifier()});
}

inline CharParserPtr optional_reference_or_pointer() { return optional(any_of(create_literal_parsers({"*", "&"}))); };

inline CharParserPtr add_optional_type_surroundings(CharParserPtr base_parser) {
    return sequence(whitespace_between(
                        {optional(literal("const")), optional(any_of(create_literal_parsers(cpp_sign_specifier))),
                         any_of({sequence({optional(any_of(create_literal_parsers(cpp_size_specifier))), base_parser}),
                                 // NOTE: this one represents the fact that short short is a valid type representing
                                 // short short int making int an optional thing.
                                 if_then(any_of({create_literal_parsers(cpp_size_specifier)}), optional(base_parser))}),

                         optional_reference_or_pointer()}),
                    "type_with_optional_reference for " + base_parser->name);
}

CharParserPtr get_templated_type_parser();

// TODO: Delete this.
inline CharParserPtr lambda_type_parser() {
    return sequence({literal("std::function<"), get_templated_type_parser(),
                     nested_string_pair(comma_separated_sequence_parser(get_templated_type_parser()),
                                        "lambda_parameters", "(", ")"),
                     until_char({'>'})},
                    "lambda_type");
}

inline CharParserPtr full_non_recursive_type = add_optional_type_surroundings(optionally_namespaced_identifier());

// NOTE: the order in which this is parsed matters a lot, because given something like std::function<void(int)>, if we
// run the non recurisve type on this we'd find up to std::function, instead we want most specific to least specific I
// thinki
inline CharParserPtr type = add_optional_type_surroundings(get_templated_type_parser());

inline CharParserPtr assignment_parser =
    sequence(whitespace_between({type, variable(), literal("="), until_char({';'})}), "assignment");

inline CharParserPtr declaration_parser =
    sequence(whitespace_between({type, variable(), until_char({';'})}), "declaration");

inline CharParserPtr parameter_parser =
    sequence(whitespace_between({optional(type_qualifier_sequence()), type, variable(),
                                 optional(default_value_for_parameter_suffix_parser)}),
             "parameter");

inline CharParserPtr optional_parameter_sequence =
    optional(repeating(sequence({literal(","), parameter_parser}, "comma_parameter"), "repeating_parameter_sequence"),
             "optional_parameter_sequence");

// TODO: need to turn this into it's own thing which is an optional comma separated sequence, I want to create a class
// out of this, what we do is that we pass in an element parser, and it does this logic.
inline CharParserPtr optional_parameters =
    optional(if_then(parameter_parser, optional_parameter_sequence, "one_or_more_parameter"), "optional_parameters");

inline CharParserPtr parameter_tuple_parser =
    sequence(whitespace_between({literal("("), optional_parameters, literal(")")}), "parameter_tuple");

inline std::vector<CharParserPtr> make_operator_literals() {
    std::vector<CharParserPtr> result;
    result.reserve(overloadable_operators.size());
    for (auto &op : overloadable_operators) {
        result.push_back(literal(op));
    }
    return result;
}

inline std::vector<CharParserPtr> operator_literals = make_operator_literals();

inline CharParserPtr optionally_namespaced_variable_parser =
    sequence({optional(sequence({variable(), literal("::")})), variable()}, "optionally_namespaced_variable");

inline CharParserPtr function_invocation =
    sequence(whitespace_between({optionally_namespaced_variable_parser, matching_string_pair("parens", "(", ")")}),
             "function_invocation");

inline CharParserPtr initializer_list_parser =
    sequence({literal(":"), comma_separated_sequence_parser(function_invocation)}, "initializer_list");

inline CharParserPtr constructor_def_parser = sequence({optionally_namespaced_variable_parser, parameter_tuple_parser,
                                                        optional(initializer_list_parser), matching_string_pair()},
                                                       "constructor_def_parser");

inline CharParserPtr base_function_signature_parser =
    sequence(whitespace_between({
                 type,
                 any_of({optionally_namespaced_variable_parser, any_of(operator_literals)}),
             }),
             "base_function_signature");

// TOOD: give the optional const thing a name
inline CharParserPtr function_signature_parser =
    sequence(whitespace_between({base_function_signature_parser, parameter_tuple_parser, optional(literal("const"))}),
             "function_signature");

inline CharParserPtr function_def_parser =
    sequence(whitespace_between({function_signature_parser, matching_string_pair()}), "function_def");

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
    sequence(whitespace_between({literal(":"), optional(access_specifier_parser), variable()}), "class_inheritance");

// NOTE: this is hollow
inline CharParserPtr class_def_parser =
    sequence(whitespace_between({literal("class"), variable(), optional(class_inheritance_parser),
                                 matching_string_pair(), literal(";")}),
             "class_def");

// NOTE: doesn't yet support nested classes.
inline CharParserPtr class_def_parser_good = sequence(
    whitespace_between({literal("class"), variable(), optional(class_inheritance_parser),
                        nested_string_pair(repeating(any_of({sequence(whitespace_between({literal("public:")})),
                                                             sequence(whitespace_between({literal("private:")})),
                                                             assignment_parser, declaration_parser}))),
                        literal(";")}),
    "class_def");

inline CharParserPtr struct_def_parser_good = sequence(
    whitespace_between({literal("struct"), variable(), optional(class_inheritance_parser),
                        nested_string_pair(repeating(any_of({sequence(whitespace_between({literal("public:")})),
                                                             sequence(whitespace_between({literal("private:")})),
                                                             assignment_parser, declaration_parser}))),
                        literal(";")}),
    "struct_def");

inline CharParserPtr enum_class_def_parser =
    sequence(whitespace_between({literal("enum class"), variable(), optional(class_inheritance_parser),
                                 nested_string_pair(comma_separated_sequence_parser(variable())), literal(";")}),
             "enum_class_def");

inline CharParserPtr using_statement_parser = sequence(
    {
        literal("using"),
        variable(),
        literal("="),
        base_type(),
        literal(";"),
    },
    "using_statement");

inline CharParserPtr struct_def_parser =
    sequence(whitespace_between({literal("struct"), variable(), matching_string_pair(), literal(";")}), "struct_def");

inline CharParserPtr source_file_body_parser =
    repeating(any_of({function_def_parser, constructor_def_parser, assignment_parser,
                      // NOTE: are classes, strutcs, enums ever evne in the source file or headers only?
                      class_def_parser, struct_def_parser, enum_class_def_parser, using_statement_parser}),
              "source_file_body");

inline CharParserPtr source_file_namespace_body_parser =
    sequence(whitespace_between({literal("namespace"), variable(), nested_string_pair(source_file_body_parser)}),
             "source_file_namespace_body");

inline CharParserPtr local_or_system_includes_parser =
    repeating(any_of({local_include_parser, system_include_parser}), "local_or_system_includes_parser");

inline CharParserPtr source_file_parser = sequence(
    {optional(local_or_system_includes_parser), any_of({source_file_namespace_body_parser, source_file_body_parser})},
    "source_file");

inline CharParserPtr header_file_parser = sequence(
    {optional(local_or_system_includes_parser), any_of({source_file_namespace_body_parser, source_file_body_parser})},
    "source_file");

std::unordered_map<std::string, std::vector<std::string>>
get_parser_name_to_matches_for_source_file(const std::string &source_code_path);
std::vector<std::string> extract_top_level_functions(const std::string &source_code_path);
std::vector<std::string> extract_top_level_classes(const std::string &source_code_path);
std::vector<std::string> extract_top_level_enum_classes(const std::string &source_code_path);

inline void test() {
    // test_parser("std::unordered_map<std::string, std::vector<std::string>>",
    //             type());
    // test_parser(" int x ", parameter_parser);
    // test_parser("  (int x, int y) ", parameter_tuple_parser);
    // test_parser("abc123", identifier());
    // test_parser("3bc123", identifier());
    // test_parser("const std::unordered_map<std::vector<std::string>, const unsigned int>",
    // get_templated_type_parser());

    // test_parser("std::function<glm::vec3(double)>", lambda_type_parser());
    test_parser("std::function<glm::vec3(double)>", type);
    // test_parser("std::function<glm::vec3(double)> f", parameter_parser);

    // // TODO: was figuring out why this doesn't work., is the comment removing it no...
    // test_parser(" glm::vec3 compute_tangent_finite_difference(std::function<glm::vec3(double)> f, double t, double "
    //             "delta) { glm::vec3 forward = f(t + delta); glm::vec3 backward = f(t - delta); return (forward - "
    //             "backward) / static_cast<float>(2.0f * delta); // central difference } ",
    //             function_def_parser);
    //
    // test_parser("std::vector<Rectangle> vertical_weighted_subdivision(const Rectangle &rect, const "
    //             "std::vector<unsigned int> &weights) { return weighted_subdivision(rect, weights); }",
    //             function_def_parser);
    //
    // test_parser("Grid::Grid(int rows, int cols, float width, float height, float origin_x, float origin_y, float "
    //             "origin_z) : rows(rows), cols(cols), grid_width(width), grid_height(height), origin_x(origin_x), "
    //             "origin_y(origin_y), origin_z(origin_z), rect_width(width / cols), rect_height(height / rows) {}",
    //             constructor_def_parser);
    // test_parser("  int add(int x, int y) ", function_signature_parser);
    // test_parser("  int add(int x, int y) { return x + y; } ",
    //             function_def_parser);
    // test_parser("  std::optional<int> opt_mul(int x, int y) ",
    //             function_signature_parser);
    //
    // test_parser("  int x = 5;", assignment_parser);
    // test_parser("  std::vector<int> x = 5;", assignment_parser);
    // test_parser("  std::vector<std::vector<std::string>> x = 6;",
    //             assignment_parser); // success
    //
    // test_parser(
    //     "std::unordered_map<std::string, std::vector<std::string>> "
    //     "collect_matches_by_parser_name(const "
    //     "ParseResult &result, const std::vector<std::string> &target_names) ",
    //     function_signature_parser); // success
    //
    // test_parser("  std::vector<std::vector<std::string>> x = \"test;test\";",
    //             assignment_parser);
    // test_parser("  _private = count123", assignment_parser);
    // test_parser("  CONST_THING = variable_123", assignment_parser);
    // test_parser("  foo = bar", assignment_parser);
    // test_parser("foo=123", assignment_parser);     // 123 is not a variable
    // test_parser("int = value", assignment_parser); // "int" is a keyword -> reject
    // test_parser(" _var = _x2", assignment_parser);
    // test_parser("foo bar", assignment_parser); // fail (missing '=')

    // try {
    //     std::string commentless_code = remove_comments_from_file("main.cpp");
    //     std::string flattened = text_utils::remove_newlines(commentless_code);
    //     flattened = text_utils::collapse_whitespace(flattened);
    //     std::cout << flattened << std::endl;
    //
    //     test_parser(flattened, source_file_parser);
    //
    //     ParseResult root = source_file_parser->parse(flattened, 0);
    //     std::vector<std::string> target_parsers = {function_def_parser->name,
    //     assignment_parser->name,
    //                                                struct_def_parser->name,
    //                                                class_def_parser->name};
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
