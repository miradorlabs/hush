import Foundation

/// Minimal dotenv parser: KEY=VALUE lines, optional `export ` prefix,
/// single/double quotes stripped, # comments and blank lines ignored.
enum DotEnv {
    static func parse(_ text: String) -> [(key: String, value: String)] {
        var result: [(String, String)] = []
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: false) {
            var line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            if line.hasPrefix("export ") { line = String(line.dropFirst(7)).trimmingCharacters(in: .whitespaces) }
            guard let eq = line.firstIndex(of: "=") else { continue }
            let key = String(line[..<eq]).trimmingCharacters(in: .whitespaces)
            var value = String(line[line.index(after: eq)...]).trimmingCharacters(in: .whitespaces)
            if value.count >= 2 {
                if (value.hasPrefix("\"") && value.hasSuffix("\"")) || (value.hasPrefix("'") && value.hasSuffix("'")) {
                    value = String(value.dropFirst().dropLast())
                }
            }
            guard !key.isEmpty else { continue }
            result.append((key, value))
        }
        return result
    }
}
