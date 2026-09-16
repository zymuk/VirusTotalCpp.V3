#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "vtapi/version.hpp"

namespace {

// Parsed command line. Options come before the command; everything after the
// command name is command-specific and left untouched by the parser.
struct CliOptions {
    std::string api_key;
    std::string base_url = "https://www.virustotal.com/api/v3";
    int timeout_seconds = 30;
    bool verify_ssl = true;
    double requests_per_minute = 4.0;
    std::string command;
    std::vector<std::string> args;
};

void print_usage(std::ostream& out) {
    out << "Usage: vtapi_eicar [options] <command> [args]\n"
           "\n"
           "Commands:\n"
           "  version                     print the library version\n"
           "  report --hash <hash>        report whether a file was scanned\n"
           "  scan-file --path <path>     upload a file for scanning\n"
           "\n"
           "Options:\n"
           "  --key <key>                 API key (falls back to $VIRUSTOTAL_API_KEY)\n"
           "  --base-url <url>            API base URL\n"
           "  --timeout <seconds>         HTTP timeout in seconds\n"
           "  --no-verify-ssl             disable TLS certificate verification\n"
           "  --rpm <n>                   requests per minute\n";
}

// Returns false (usage error) when an option is unknown or missing its value.
bool parse_options(const std::vector<std::string>& args, CliOptions& out) {
    std::size_t i = 0;
    for (; i < args.size(); ++i) {
        const std::string& arg = args[i];
        if (arg == "--key" || arg == "--base-url" || arg == "--timeout" ||
            arg == "--rpm") {
            if (i + 1 >= args.size())
                return false;
            const std::string& value = args[++i];
            if (arg == "--key")
                out.api_key = value;
            else if (arg == "--base-url")
                out.base_url = value;
            else if (arg == "--timeout") {
                try {
                    out.timeout_seconds = std::stoi(value);
                } catch (...) {
                    return false;
                }
            } else {
                try {
                    out.requests_per_minute = std::stod(value);
                } catch (...) {
                    return false;
                }
            }
        } else if (arg == "--no-verify-ssl") {
            out.verify_ssl = false;
        } else if (!arg.empty() && arg[0] == '-') {
            return false; // unknown option
        } else {
            out.command = arg;
            out.args.assign(args.begin() + static_cast<std::ptrdiff_t>(i + 1), args.end());
            return !out.command.empty();
        }
    }
    return false; // no command given
}

} // namespace

int main(int argc, char** argv) {
    CliOptions opts;
    if (!parse_options(std::vector<std::string>(argv + 1, argv + argc), opts)) {
        print_usage(std::cerr);
        return 2;
    }

    if (opts.api_key.empty()) {
        if (const char* env = std::getenv("VIRUSTOTAL_API_KEY"))
            opts.api_key = env;
    }

    if (opts.command != "version" && opts.api_key.empty()) {
        std::cerr << "error: API key required (--key or $VIRUSTOTAL_API_KEY)\n";
        return 2;
    }

    if (opts.command == "version") {
        std::cout << vtapi::version_string() << "\n";
        return 0;
    }

    std::cerr << "error: unknown or unimplemented command: " << opts.command << "\n";
    print_usage(std::cerr);
    return 2;
}