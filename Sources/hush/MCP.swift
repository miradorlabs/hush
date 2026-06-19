import Foundation

/// hush's MCP secrets gateway: a stdio JSON-RPC 2.0 server an AI tool launches so
/// it never holds plaintext `.env` secrets directly — it requests them, and every
/// request runs through hush's full check path (location + signature + config
/// binding) and a Secure Enclave Touch ID prompt that names the caller and the
/// key. It is hand-rolled on Foundation only, to keep hush's zero-dependency
/// guarantee.
///
/// Honest scope: once `get_secret` returns a value, the (possibly compromised)
/// assistant holds it. What the gateway buys is per-access *consent you can see*,
/// a complete *audit trail*, *least-privilege* scoping (`.hushmcp.json`), and the
/// `http_request` reference-handle path where a secret is used for a network call
/// without ever entering the model's context.
enum MCP {
    static let serverVersion = "1.0.0"
    static let defaultProtocolVersion = "2025-06-18"
    static let maxResponseBody = 16 * 1024

    static func serve(args: [String]) -> Never {
        mcpStdoutGuard = true // stdout is reserved for JSON-RPC frames from here on
        var projectDir = FileManager.default.currentDirectoryPath
        var file = defaultSecretsFile
        var it = args.makeIterator()
        while let a = it.next() {
            switch a {
            case "--project": if let v = it.next() { projectDir = v }
            case "-f", "--file": if let v = it.next() { file = v }
            case "-h", "--help":
                print("""
                hush mcp — run the secrets gateway as an MCP (stdio) server.

                Point your AI tool's MCP config at `hush mcp` with the project as
                cwd (or pass --project DIR). Tools: list_secrets, get_secret,
                http_request. Least-privilege via a project-local .hushmcp.json:
                  { "allow": ["DB_*"], "deny": ["AWS_*"], "http_allow_hosts": ["api.x.com"] }
                Every secret request prompts Touch ID and is written to the access log.
                """)
                exit(0)
            default: break
            }
        }
        note("hush mcp serving for project \(projectDir) (file \(file))")
        Server(projectDir: projectDir, file: file).run()
        exit(0)
    }

    final class Server {
        let projectDir: String
        let secretsPath: String

        init(projectDir: String, file: String) {
            self.projectDir = projectDir
            self.secretsPath = URL(fileURLWithPath: projectDir).appendingPathComponent(file).path
        }

        func run() {
            // Newline-delimited JSON over stdin/stdout (the MCP stdio transport).
            while let line = readLine(strippingNewline: true) {
                if line.isEmpty { continue }
                guard let data = line.data(using: .utf8),
                      let msg = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                    continue // ignore anything that isn't a JSON object
                }
                if let reply = handle(msg) { send(reply) }
            }
        }

        // MARK: - dispatch (pure; returns the response object, or nil for notifications)

        func handle(_ msg: [String: Any]) -> [String: Any]? {
            let id = msg["id"]
            switch msg["method"] as? String {
            case "initialize":
                return response(id: id, result: initializeResult(msg["params"] as? [String: Any]))
            case "notifications/initialized", "notifications/cancelled":
                return nil
            case "ping":
                return response(id: id, result: [:])
            case "tools/list":
                return response(id: id, result: ["tools": Self.toolDefinitions])
            case "tools/call":
                return response(id: id, result: callTool(msg["params"] as? [String: Any] ?? [:]))
            case .some(let method):
                guard id != nil else { return nil }
                return errorResponse(id: id, code: -32601, message: "method not found: \(method)")
            case .none:
                return nil
            }
        }

        func initializeResult(_ params: [String: Any]?) -> [String: Any] {
            let version = (params?["protocolVersion"] as? String) ?? MCP.defaultProtocolVersion
            return [
                "protocolVersion": version,
                "capabilities": ["tools": [String: Any]()],
                "serverInfo": ["name": "hush", "version": MCP.serverVersion],
                "instructions": """
                Secrets for this project are served only through these tools. Never \
                read .env, .hush, or config files directly. Use get_secret(name) for \
                a value, or http_request with {{secret:NAME}} placeholders so the \
                value is used for a request without ever entering your context. Every \
                request prompts the user for Touch ID and is logged.
                """,
            ]
        }

        // MARK: - tools

        static let toolDefinitions: [[String: Any]] = [
            [
                "name": "list_secrets",
                "description": "List the names (never the values) of the secrets available for this project. Requires Touch ID.",
                "inputSchema": ["type": "object", "properties": [String: Any](), "additionalProperties": false],
            ],
            [
                "name": "get_secret",
                "description": "Return the value of one secret by name. Prompts the user for Touch ID and is audited. Subject to the project's least-privilege policy.",
                "inputSchema": [
                    "type": "object",
                    "properties": ["name": ["type": "string", "description": "the secret's key, e.g. DATABASE_URL"]],
                    "required": ["name"],
                    "additionalProperties": false,
                ],
            ],
            [
                "name": "http_request",
                "description": "Make an HTTP request where header values and the body may contain {{secret:NAME}} placeholders. hush substitutes the real secret server-side so it never enters your context, and returns the response. Only hosts allowlisted in .hushmcp.json are permitted. Prompts Touch ID.",
                "inputSchema": [
                    "type": "object",
                    "properties": [
                        "url": ["type": "string"],
                        "method": ["type": "string", "description": "GET, POST, … (default GET)"],
                        "headers": ["type": "object", "description": "header name → value; values may contain {{secret:NAME}}"],
                        "body": ["type": "string", "description": "request body; may contain {{secret:NAME}}"],
                    ],
                    "required": ["url"],
                    "additionalProperties": false,
                ],
            ],
        ]

        func callTool(_ params: [String: Any]) -> [String: Any] {
            let name = params["name"] as? String ?? ""
            let args = params["arguments"] as? [String: Any] ?? [:]
            switch name {
            case "list_secrets": return listSecrets()
            case "get_secret": return getSecret(args)
            case "http_request": return httpRequest(args)
            default: return Self.toolError("unknown tool: \(name)")
            }
        }

        private func listSecrets() -> [String: Any] {
            let policy = GatewayPolicy.load(projectDir: projectDir)
            do {
                let pairs = try secrets(action: "MCP list_secrets", reason: "List secret names for")
                let names = pairs.map(\.key).filter { policy.allowsKey($0) }.sorted()
                let body = names.isEmpty ? "(no secrets available under the current policy)" : names.joined(separator: "\n")
                return Self.toolOK(body)
            } catch { return Self.toolError("\(error)") }
        }

        private func getSecret(_ args: [String: Any]) -> [String: Any] {
            guard let name = args["name"] as? String, !name.isEmpty else {
                return Self.toolError("get_secret requires a non-empty `name`")
            }
            let policy = GatewayPolicy.load(projectDir: projectDir)
            guard policy.allowsKey(name) else {
                AuditLog.record(.blocked, action: "MCP get_secret \(name)", detail: "denied by .hushmcp.json policy")
                return Self.toolError("access to \(name) is denied by this project's hush MCP policy")
            }
            do {
                let pairs = try secrets(action: "MCP get_secret \(name)", reason: "Reveal \(name) to the MCP client")
                guard let value = pairs.last(where: { $0.key == name })?.value else {
                    return Self.toolError("no secret named \(name)")
                }
                return Self.toolOK(value)
            } catch { return Self.toolError("\(error)") }
        }

        private func httpRequest(_ args: [String: Any]) -> [String: Any] {
            guard let urlString = args["url"] as? String, let url = URL(string: urlString), let host = url.host else {
                return Self.toolError("http_request requires a valid absolute `url`")
            }
            let method = (args["method"] as? String ?? "GET").uppercased()
            var headers = (args["headers"] as? [String: Any] ?? [:]).compactMapValues { $0 as? String }
            let body = args["body"] as? String

            let policy = GatewayPolicy.load(projectDir: projectDir)
            guard policy.allowsHost(host) else {
                AuditLog.record(.blocked, action: "MCP http_request \(method) \(host)", detail: "host not in http_allow_hosts")
                return Self.toolError("policy denies sending secrets to \(host); add it to \"http_allow_hosts\" in .hushmcp.json")
            }
            // Which secrets does this request reference, and are they all allowed?
            let referenced = Set(headers.values.flatMap(SecretTemplating.referencedNames) + (body.map(SecretTemplating.referencedNames) ?? []))
            for n in referenced where !policy.allowsKey(n) {
                AuditLog.record(.blocked, action: "MCP http_request \(method) \(host)", detail: "secret \(n) denied by policy")
                return Self.toolError("access to \(n) is denied by this project's hush MCP policy")
            }

            do {
                let pairs = try secrets(action: "MCP http_request \(method) \(host) using \(referenced.sorted().joined(separator: ","))",
                                        reason: "Send \(referenced.isEmpty ? "a request" : referenced.sorted().joined(separator: ", ")) to \(host)")
                let map = Dictionary(pairs.map { ($0.key, $0.value) }, uniquingKeysWith: { _, last in last })
                var missing: [String] = []
                for (k, v) in headers {
                    let s = SecretTemplating.substitute(in: v, lookup: { map[$0] })
                    headers[k] = s.result; missing += s.missing
                }
                var resolvedBody = body
                if let body {
                    let s = SecretTemplating.substitute(in: body, lookup: { map[$0] })
                    resolvedBody = s.result; missing += s.missing
                }
                if !missing.isEmpty {
                    return Self.toolError("unknown secret(s) referenced: \(Set(missing).sorted().joined(separator: ", "))")
                }
                let (status, respBody) = Self.performHTTP(method: method, url: url, headers: headers, body: resolvedBody)
                // Scrub in case the endpoint echoes a secret back, so it can't
                // re-enter the model context through the response.
                let safe = SecretScrub.apply(String(respBody.prefix(MCP.maxResponseBody)))
                return Self.toolOK("HTTP \(status)\n\(safe)")
            } catch { return Self.toolError("\(error)") }
        }

        /// Decrypt this project's secrets through the shared check path (Touch ID).
        private func secrets(action: String, reason: String) throws -> [(key: String, value: String)] {
            let data = try openSealedCore(path: secretsPath, action: action, reasonPrefix: reason)
            return DotEnv.parse(String(decoding: data, as: UTF8.self))
        }

        // MARK: - HTTP

        static func performHTTP(method: String, url: URL, headers: [String: String], body: String?) -> (status: Int, body: String) {
            var req = URLRequest(url: url)
            req.httpMethod = method
            for (k, v) in headers { req.setValue(v, forHTTPHeaderField: k) }
            if let body, !body.isEmpty { req.httpBody = Data(body.utf8) }
            req.timeoutInterval = 20
            let sem = DispatchSemaphore(value: 0)
            var status = 0
            var out = ""
            URLSession.shared.dataTask(with: req) { data, resp, err in
                if let http = resp as? HTTPURLResponse { status = http.statusCode }
                if let data, !data.isEmpty { out = String(decoding: data, as: UTF8.self) }
                else if let err { out = "request error: \(err.localizedDescription)" }
                sem.signal()
            }.resume()
            sem.wait()
            return (status, out)
        }

        // MARK: - JSON-RPC envelopes

        static func toolOK(_ text: String) -> [String: Any] { ["content": [["type": "text", "text": text]], "isError": false] }
        static func toolError(_ text: String) -> [String: Any] { ["content": [["type": "text", "text": text]], "isError": true] }

        func response(id: Any?, result: [String: Any]) -> [String: Any] {
            var obj: [String: Any] = ["jsonrpc": "2.0", "result": result]
            obj["id"] = id ?? NSNull()
            return obj
        }

        func errorResponse(id: Any?, code: Int, message: String) -> [String: Any] {
            ["jsonrpc": "2.0", "id": id ?? NSNull(), "error": ["code": code, "message": message]]
        }

        private func send(_ obj: [String: Any]) {
            guard let data = try? JSONSerialization.data(withJSONObject: obj) else { return }
            FileHandle.standardOutput.write(data)
            FileHandle.standardOutput.write(Data("\n".utf8))
        }
    }
}
