#include "cpp_parsing.hpp"
#include <queue>

namespace cpp_parsing {

ParseResult clean_parse_result(const ParseResult &r) {
    // Copy the current result
    ParseResult cleaned = r;

    // Recursively clean children
    std::vector<ParseResult> new_sub_results;
    new_sub_results.reserve(cleaned.sub_results.size());

    for (const auto &sub : cleaned.sub_results) {
        // Only keep if it actually matched something
        if (sub.start != sub.end) {
            new_sub_results.push_back(clean_parse_result(sub));
        }
    }

    cleaned.sub_results = std::move(new_sub_results);
    return cleaned;
}

// NOTE: next we have some operations on a parse result, I believe pointers are used here because outside the function
// we initialize to nullopt making it operate like an optional, so I think optionals could be used instead here.

// Find the first node in the tree whose parser_name equals `target` (DFS).
const cpp_parsing::ParseResult *find_first_by_name(const cpp_parsing::ParseResult *root, const std::string &target) {
    if (!root)
        return nullptr;
    if (root->parser_name == target)
        return root;
    for (const auto &c : root->sub_results) {
        if (const cpp_parsing::ParseResult *r = find_first_by_name(&c, target))
            return r;
    }
    return nullptr;
}

// Find any node whose parser_name contains substring `substr`. Example: "type_with_optional_reference".
const cpp_parsing::ParseResult *find_first_name_contains(const cpp_parsing::ParseResult *root,
                                                         const std::string &substr) {
    if (!root)
        return nullptr;
    if (root->parser_name.find(substr) != std::string::npos)
        return root;
    for (const auto &c : root->sub_results) {
        if (const cpp_parsing::ParseResult *r = find_first_name_contains(&c, substr))
            return r;
    }
    return nullptr;
}

// recursively collect all nodes with parser_name == target (DFS)
void collect_by_name(const cpp_parsing::ParseResult *root, const std::string &target,
                     std::vector<const cpp_parsing::ParseResult *> &out) {
    if (!root)
        return;
    if (root->parser_name == target)
        out.push_back(root);
    for (const auto &c : root->sub_results)
        collect_by_name(&c, target, out);
}

std::vector<std::pair<std::string, std::string>> bfs_collect_matches(const cpp_parsing::ParseResult *root,
                                                                     const std::vector<std::string> &names) {
    std::vector<std::pair<std::string, std::string>> results;
    if (!root)
        return results;

    std::unordered_set<std::string> name_set(names.begin(), names.end());

    std::queue<const cpp_parsing::ParseResult *> q;
    q.push(root);

    while (!q.empty()) {
        const cpp_parsing::ParseResult *cur = q.front();
        q.pop();

        if (name_set.count(cur->parser_name)) {
            results.emplace_back(cur->parser_name, node_text(cur));
        }

        for (const auto &c : cur->sub_results) {
            q.push(&c);
        }
    }

    return results;
}

// Join a node's match text, but try prefer more precise child matches when available.
// Here we return trimmed 'match' for simplicity (you can refine to assemble tokens).
std::string node_text(const cpp_parsing::ParseResult *node) {
    if (!node)
        return {};
    if (!text_utils::trim(node->match).empty())
        return text_utils::trim(node->match);
    // fallback: try to concatenate children
    std::string acc;
    for (const auto &c : node->sub_results) {
        if (!acc.empty())
            acc += " ";
        acc += text_utils::trim(c.match);
    }
    return text_utils::trim(acc);
}

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

CharParserPtr matching_pair(CharParserPtr left_parser, CharParserPtr right_parser, const std::string &name) {
    return std::make_shared<MatchingPairParser>(left_parser, right_parser, name);
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

std::string remove_macros(const std::string &code) {
    std::istringstream iss(code);
    std::ostringstream oss;
    std::string line;

    while (std::getline(iss, line)) {
        // Trim leading spaces
        std::string trimmed = line;
        trimmed.erase(trimmed.begin(),
                      std::find_if(trimmed.begin(), trimmed.end(), [](unsigned char c) { return !std::isspace(c); }));

        // Skip preprocessor lines
        if (!trimmed.empty() && trimmed[0] == '#') {
            continue;
        }

        oss << line << "\n";
    }

    return oss.str();
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

ParseResult parse_source_or_header_file(const std::string &source_code_path) {
    std::string commentless_code = remove_comments_from_file(source_code_path);
    // NOTE: I'm removing macros, because I am using the source file parser on header files as well
    // and that is the only difference that I've encountered so far (which is clearly wrong), but works for now.
    commentless_code = remove_macros(commentless_code);
    std::string flattened = text_utils::remove_newlines(commentless_code);
    flattened = text_utils::collapse_whitespace(flattened);

    ParseResult root = source_file_parser->parse(flattened, 0);
    auto cleaned_root = clean_parse_result(root);

    return cleaned_root;
}

std::unordered_map<std::string, std::vector<std::string>>
get_parser_name_to_matches_for_source_file(const std::string &source_code_path) {
    // logger.disable_all_levels();
    try {
        std::string commentless_code = remove_comments_from_file(source_code_path);
        // NOTE: I'm removing macros, because I am using the source file parser on header files as well
        // and that is the only difference that I've encountered so far (which is clearly wrong), but works for now.
        commentless_code = remove_macros(commentless_code);
        std::string flattened = text_utils::remove_newlines(commentless_code);
        flattened = text_utils::collapse_whitespace(flattened);

        ParseResult root = source_file_parser->parse(flattened, 0);
        auto cleaned_root = clean_parse_result(root);

        auto match_map = collect_matches_by_parser_name(root);
        return match_map;
    } catch (const std::exception &e) {
        std::cerr << "Error in get_parser_name_to_matches_for_source_file: " << e.what() << '\n';
        return {};
    }
}

std::vector<std::string> extract_all_matches_for_a_particular_parser(const std::string &source_code_path,
                                                                     const std::string &parser_name) {
    logger.disable_all_levels();
    try {
        auto match_map = get_parser_name_to_matches_for_source_file(source_code_path);

        auto it = match_map.find(parser_name);
        if (it != match_map.end()) {
            return it->second;
        }

        return {}; // No matches found
    } catch (const std::exception &e) {
        std::cerr << "Error in extract_top_level_functions: " << e.what() << '\n';
        return {};
    }
}

// NOTE: having multiple of these seems expensive for no reason.
std::vector<std::string> extract_top_level_functions(const std::string &source_code_path) {
    return extract_all_matches_for_a_particular_parser(source_code_path, function_def_parser->name);
}

std::vector<std::string> extract_top_level_classes(const std::string &source_code_path) {
    return extract_all_matches_for_a_particular_parser(source_code_path, class_def_parser->name);
}

std::vector<std::string> extract_top_level_enum_classes(const std::string &source_code_path) {
    return extract_all_matches_for_a_particular_parser(source_code_path, enum_class_def_parser->name);
}

CharParserPtr get_templated_type_parser() {
    auto templated_type_recursive_placeholder = std::make_shared<DeferredParser>();

    CharParserPtr integer_literal_parser = std::make_shared<DecimalLiteralParser>();
    // TODO: expand later for full constant-expression support

    CharParserPtr template_argument = any_of(
        {
            templated_type_recursive_placeholder, // type argument (recursive)
            integer_literal_parser                // constant argument
        },
        "template_argument");

    CharParserPtr template_argument_list = sequence(
        {template_argument, optional(repeating(sequence(whitespace_between({literal(","), template_argument}))))},
        "template_argument_list");

    full_non_recursive_type->name = "non_templated_type";

    // templated type: e.g. std::vector<int>, std::array<float, 3>
    CharParserPtr templated_type_parser = add_optional_type_surroundings(sequence(
        whitespace_between({optionally_namespaced_identifier(), literal("<"), template_argument_list, literal(">")})));

    // TODO: using a template argument list here is wrong, it should be a comme seqpearated sequence of
    // templated_type_recursive_placeholder instead
    CharParserPtr lambda_function_signature_type_parser = add_optional_type_surroundings(sequence(whitespace_between(
        {templated_type_recursive_placeholder, literal("("), template_argument_list, literal(")")})));
    lambda_function_signature_type_parser->name = "lambda_function_signature_type_parser";

    CharParserPtr lambda_function_type_parser = add_optional_type_surroundings(sequence(whitespace_between(
        {literal("std::function"), literal("<"), lambda_function_signature_type_parser, literal(">")})));
    lambda_function_type_parser->name = "lambda_function_type_parser";

    CharParserPtr templated_type =
        any_of({templated_type_parser, lambda_function_type_parser, full_non_recursive_type}, "templated_type");

    // NOTE: define its inner content after the fact to avoid circular dependencies
    templated_type_recursive_placeholder->set_parser(templated_type);

    return templated_type;
}

} // namespace cpp_parsing
