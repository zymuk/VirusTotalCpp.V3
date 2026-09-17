#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <optional>
#include <string>
#include <vector>

#include "vtapi/client.hpp"
#include "vtapi/detail/hashing.hpp"
#include "vtapi/types.hpp"
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
           "  scan-file --path <file> [--password <pw>]  upload a file for scanning\n"
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

// Builds a library client from the parsed command line.
vtapi::ClientOptions to_client_options(const CliOptions& opts) {
    vtapi::ClientOptions opt;
    opt.api_key = opts.api_key;
    opt.base_url = opts.base_url;
    opt.verify_ssl = opts.verify_ssl;
    opt.timeout = std::chrono::seconds(opts.timeout_seconds);
    opt.requests_per_minute = opts.requests_per_minute;
    return opt;
}

// `report --hash <hash>` — step 1 of the flow: Was this file ever scanned?
// 200 → print the verdict summary; 404 → "not seen yet" and how to submit it.
int run_report(const std::vector<std::string>& args, const CliOptions& opts) {
    std::string hash;
    for (std::size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--hash" && i + 1 < args.size()) {
            hash = args[++i];
        } else {
            std::cerr << "error: report: expected --hash <hash>\n";
            print_usage(std::cerr);
            return 2;
        }
    }
    if (hash.empty()) {
        std::cerr << "error: report: missing --hash <hash>\n";
        print_usage(std::cerr);
        return 2;
    }

    try {
        vtapi::VirusTotal vt{to_client_options(opts)};
        const vtapi::FileReport report = vt.get_file_report(hash);
        const std::string resource = report.sha256.empty() ? report.id : report.sha256;

        // v3 stats: total engines = the sum of every bucket in
        // attributes.last_analysis_stats; "flagging" = engines that returned a
        // malicious or suspicious verdict (analog of v2's positives/scans).
        const vtapi::AnalysisStats& stats = report.last_analysis_stats;
        const int64_t total = stats.harmless + stats.malicious + stats.suspicious +
                              stats.timeout + stats.undetected + stats.type_unsupported;
        std::size_t flagging = 0;
        const vtapi::AnalysisResult* top = nullptr;
        for (const auto& entry : report.last_analysis_results) {
            const bool flagged = entry.second.category == "malicious" ||
                                 entry.second.category == "suspicious";
            if (flagged) {
                ++flagging;
                if (!top)
                    top = &entry.second;
            }
        }

        std::cout << "resource: " << resource << "\n";
        std::cout << "Seen before: Yes\n";
        std::cout << "Malicious: " << stats.malicious << " / Total: " << total << "\n";
        std::cout << "Engines flagging: " << flagging << "\n";
        if (top) {
            std::cout << "Top engine: " << top->engine_name;
            if (!top->result.empty())
                std::cout << " → " << top->result;
            std::cout << "\n";
        }
        return 0;
    } catch (const vtapi::NotFound&) {
        // Never scanned — a normal answer, not an error.
        std::cout << "resource: " << hash << "\n";
        std::cout << "Seen before: No\n";
        std::cout << "Run: vtapi_eicar scan-file --path <file> to submit it\n";
        return 0;
    } catch (const vtapi::VtError& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
}

// Reads a file's bytes for local hashing. Returns false when the file cannot
// be opened or read.
bool read_file(const std::string& path, std::string& out) {
    std::ifstream in(path, std::ios::binary);
    if (!in)
        return false;
    out.assign(std::istreambuf_iterator<char>(in),
               std::istreambuf_iterator<char>());
    return in.good() || in.eof();
}

// `scan-file --path <file> [--password <pw>]` — step 2 of the flow: submit the
// file, then print the analysis id plus the locally computed sha256 to look it
// up with `report --hash` once scanning completes.
int run_scan_file(const std::vector<std::string>& args, const CliOptions& opts) {
    std::string path;
    std::optional<std::string> password;
    for (std::size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--path" && i + 1 < args.size()) {
            path = args[++i];
        } else if (args[i] == "--password" && i + 1 < args.size()) {
            password = args[++i];
        } else {
            std::cerr << "error: scan-file: expected --path <file> [--password <pw>]\n";
            print_usage(std::cerr);
            return 2;
        }
    }
    if (path.empty()) {
        std::cerr << "error: scan-file: missing --path <file>\n";
        print_usage(std::cerr);
        return 2;
    }

    try {
        vtapi::VirusTotal vt{to_client_options(opts)};
        const vtapi::ScanResult result = vt.scan_file(path, password);

        // Hash locally so the follow-up lookup never depends on the server
        // echoing file_info back.
        std::string bytes;
        if (!read_file(path, bytes)) {
            std::cerr << "error: cannot read file: " << path << "\n";
            return 1;
        }
        const std::string sha256 = vtapi::detail::sha256_hex(bytes);

        std::cout << "Uploaded. analysis id: " << result.id << "\n";
        std::cout << "sha256: " << sha256 << "\n";
        std::cout << "Run: vtapi_eicar report --hash " << sha256 << "\n";
        return 0;
    } catch (const vtapi::VtError& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
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

    if (opts.command == "report")
        return run_report(opts.args, opts);

    if (opts.command == "scan-file")
        return run_scan_file(opts.args, opts);

    std::cerr << "error: unknown or unimplemented command: " << opts.command << "\n";
    print_usage(std::cerr);
    return 2;
}