#include "cpp_parsing.hpp"

namespace cpp_parsing {

std::ostream &print_parse_result(std::ostream &os, const ParseResult &result, int indent) {
    std::string indent_str(indent * 2, ' ');
    os << indent_str << "ParseResult {\n";
    os << indent_str << "  succeeded: " << (result.succeeded ? "true" : "false") << "\n";
    os << indent_str << "  parser_name: \"" << result.parser_name << "\"\n";
    os << indent_str << "  start: " << result.start << ", end: " << result.end << "\n";
    os << indent_str << "  match: \"" << result.match << "\"\n";

    if (!result.sub_results.empty()) {
        os << indent_str << "  sub_results: [\n";
        for (const auto &sub : result.sub_results) {
            cpp_parsing::print_parse_result(os, sub, indent + 2);
        }
        os << indent_str << "  ]\n";
    }

    os << indent_str << "}\n";
    return os;
}

std::ostream &operator<<(std::ostream &os, const ParseResult &result) { return print_parse_result(os, result); }

CharParserPtr optional_whitespace() { return std::make_shared<OptionalWhitespaceParser>(); }
CharParserPtr variable() { return std::make_shared<VariableParser>(); }
CharParserPtr type() { return std::make_shared<TypeParser>(); }
CharParserPtr type_qualifier_sequence() { return std::make_shared<TypeQualifierSequenceParser>(); }

CharParserPtr until_char(std::vector<char> target_chars, bool inclusive, bool ignore_in_strings_and_chars,
                         const std::string &name) {
    return std::make_shared<UntilCharParser>(target_chars, inclusive, ignore_in_strings_and_chars, name);
}

CharParserPtr literal(const std::string &s) { return std::make_shared<LiteralParser>(s); }

CharParserPtr matching_braces(const std::string &name) { return std::make_shared<MatchingBraceParser>(name); }

CharParserPtr nested_braces(CharParserPtr parser, const std::string &name) {
    return std::make_shared<NestedBraceParser>(parser, name);
}

CharParserPtr repeating(CharParserPtr parser, const std::string &name) {
    return std::make_shared<RepeatingParser>(parser, name);
}

CharParserPtr optional(CharParserPtr parser, const std::string &name) {
    return std::make_shared<OptionalParser>(parser, name);
}

CharParserPtr if_then(std::shared_ptr<CharParser> condition_parser, std::shared_ptr<CharParser> then_parser,
                      const std::string &name) {
    return std::make_shared<IfThenParser>(condition_parser, then_parser, name);
}

CharParserPtr any_of(std::vector<CharParserPtr> parsers, const std::string &name) {
    return std::make_shared<AnyOfParser>(parsers, name);
}

CharParserPtr sequence(std::vector<CharParserPtr> parsers, const std::string &name) {
    return std::make_shared<SequenceParser>(parsers, name);
}

std::string remove_comments_from_file(const std::string &filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Could not open file: " + filename);
    }

    std::ostringstream result;
    std::string line;
    bool in_block_comment = false;

    while (std::getline(file, line)) {
        std::string processed_line;
        size_t i = 0;
        while (i < line.length()) {
            if (!in_block_comment && i + 1 < line.length() && line[i] == '/' && line[i + 1] == '*') {
                in_block_comment = true;
                i += 2;
            } else if (in_block_comment && i + 1 < line.length() && line[i] == '*' && line[i + 1] == '/') {
                in_block_comment = false;
                i += 2;
            } else if (!in_block_comment && i + 1 < line.length() && line[i] == '/' && line[i + 1] == '/') {
                break; // ignore the rest of the line (single-line comment)
            } else if (!in_block_comment) {
                processed_line += line[i++];
            } else {
                ++i; // skip characters inside block comment
            }
        }
        if (!in_block_comment) {
            result << processed_line << '\n';
        }
    }

    return result.str();
}

std::unordered_map<std::string, std::vector<std::string>>
collect_matches_by_parser_name(const ParseResult &result, const std::vector<std::string> &target_names) {
    std::unordered_map<std::string, std::vector<std::string>> matches;
    std::unordered_set<std::string> target_set(target_names.begin(), target_names.end());

    std::function<void(const ParseResult &)> recurse = [&](const ParseResult &res) {
        if (res.succeeded && target_set.count(res.parser_name)) {
            matches[res.parser_name].push_back(res.match);
        }
        for (const auto &sub : res.sub_results) {
            recurse(sub);
        }
    };

    recurse(result);
    return matches;
}

// TODO: was figuring out why this function doesn't work even though we tested it previously

std::vector<std::string> extract_top_level_functions(const std::string &source_code_path) {
    try {
        std::cout << "extract_top_level_functions" << std::endl;
        std::cout << source_code_path << std::endl;
        // Remove comments and flatten whitespace
        std::cout << "-3" << std::endl;
        std::string commentless_code = remove_comments_from_file(source_code_path);
        std::cout << "-2" << std::endl;
        std::string flattened = text_utils::remove_newlines(commentless_code);
        std::cout << "-1" << std::endl;
        flattened = text_utils::collapse_whitespace(flattened);
        std::cout << "0" << std::endl;

        // Optional debug
        // std::cout << flattened << std::endl;

        // Parse
        ParseResult root = source_file_parser->parse(flattened, 0);
        std::cout << "1" << std::endl;

        // Collect top-level functions
        std::vector<std::string> target_parsers = {function_def_parser->name};
        auto match_map = collect_matches_by_parser_name(root, target_parsers);
        std::cout << "2" << std::endl;

        auto it = match_map.find(function_def_parser->name);
        if (it != match_map.end()) {

            std::cout << "3" << std::endl;
            return it->second;
        }
        std::cout << "4" << std::endl;

        return {}; // No matches found
    } catch (const std::exception &e) {
        std::cerr << "Error in extract_top_level_functions: " << e.what() << '\n';
        return {};
    }
}

} // namespace cpp_parsing
