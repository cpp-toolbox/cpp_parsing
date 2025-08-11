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
CharParserPtr identifier() { return std::make_shared<IdentifierParser>(); }
CharParserPtr variable() { return std::make_shared<VariableParser>(); }
CharParserPtr base_type() { return std::make_shared<TypeParser>(); }
CharParserPtr type_qualifier_sequence() { return std::make_shared<TypeQualifierSequenceParser>(); }

CharParserPtr until_char(std::vector<char> target_chars, bool inclusive, bool ignore_in_strings_and_chars,
                         const std::string &name) {
    return std::make_shared<UntilCharParser>(target_chars, inclusive, ignore_in_strings_and_chars, name);
}

CharParserPtr literal(const std::string &s) { return std::make_shared<LiteralParser>(s); }

CharParserPtr matching_string_pair(const std::string &name, std::string left, std::string right) {
    return std::make_shared<MatchingStringPairParser>(name, left, right);
}
CharParserPtr nested_string_pair(CharParserPtr parser, const std::string &name, std::string left, std::string right) {
    return std::make_shared<NestedStringPairParser>(parser, name, left, right);
}

CharParserPtr repeating(CharParserPtr parser, const std::string &name) {
    return std::make_shared<RepeatingParser>(parser, name);
}

CharParserPtr optional(CharParserPtr parser, const std::string &name) {
    return std::make_shared<OptionalParser>(parser, name);
}

CharParserPtr deferred() { return std::make_shared<DeferredParser>(); }

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
    bool restrict = !target_names.empty();

    std::function<void(const ParseResult &)> recurse = [&](const ParseResult &res) {
        if (res.succeeded && (!restrict || target_set.count(res.parser_name))) {
            matches[res.parser_name].push_back(res.match);
        }
        for (const auto &sub : res.sub_results) {
            recurse(sub);
        }
    };

    recurse(result);
    return matches;
}

std::unordered_map<std::string, std::vector<std::string>>
get_parser_name_to_matches_for_source_file(const std::string &source_code_path) {
    logger.disable_all_levels();
    try {
        std::string commentless_code = remove_comments_from_file(source_code_path);
        std::string flattened = text_utils::remove_newlines(commentless_code);
        flattened = text_utils::collapse_whitespace(flattened);

        ParseResult root = source_file_parser->parse(flattened, 0);

        auto match_map = collect_matches_by_parser_name(root);
        return match_map;
    } catch (const std::exception &e) {
        std::cerr << "Error inget_parser_name_to_matches_for_source_file: " << e.what() << '\n';
        return {};
    }
}

std::vector<std::string> extract_top_level_functions(const std::string &source_code_path) {
    try {
        auto match_map = get_parser_name_to_matches_for_source_file(source_code_path);

        auto it = match_map.find(function_def_parser->name);
        if (it != match_map.end()) {
            return it->second;
        }

        return {}; // No matches found
    } catch (const std::exception &e) {
        std::cerr << "Error in extract_top_level_functions: " << e.what() << '\n';
        return {};
    }
}

CharParserPtr get_templated_type_parser() {
    auto templated_type_recursive_placeholder = std::make_shared<DeferredParser>();

    CharParserPtr templated_type_parameter_list = sequence(
        {templated_type_recursive_placeholder,
         optional(repeating(sequence(whitespace_between({literal(","), templated_type_recursive_placeholder}))))},
        "templated_type_parameter_list");

    full_non_recursive_type->name = "non_templated_type";

    CharParserPtr templated_type_parser = add_optional_type_surroundings(sequence(whitespace_between(
        {optionally_namespaced_identifier(), literal("<"), templated_type_parameter_list, literal(">")})));

    CharParserPtr lambda_function_signature_type_parser = add_optional_type_surroundings(sequence(whitespace_between(
        {templated_type_recursive_placeholder, literal("("), templated_type_parameter_list, literal(")")})));
    lambda_function_signature_type_parser->name = "lambda_function_signature_type_parser";

    CharParserPtr lambda_function_type_parser = add_optional_type_surroundings(sequence(whitespace_between(
        {literal("std::function"), literal("<"), lambda_function_signature_type_parser, literal(">")})));
    lambda_function_type_parser->name = "lambda_function_type_parser";

    CharParserPtr templated_type =
        any_of({templated_type_parser, lambda_function_type_parser, full_non_recursive_type}, // base case
               "templated_type");

    // NOTE: define its inner content after the fact to avoid circular dependencies
    templated_type_recursive_placeholder->set_parser(templated_type);

    return templated_type;
}

} // namespace cpp_parsing
