import Foundation

// Process-wide constants and flags shared across the module.
//
// IMPORTANT: these live here, NOT in main.swift. Top-level variable bindings in
// main.swift are initialized inline as the executable's implicit `main` runs —
// they are *not* given the lazy, run-once initialization that globals in every
// other file get. The test bundle `@testable import`s this module but never runs
// `main`, so a global declared in main.swift stays uninitialized there; reading
// it (e.g. AuditLog reading `identityDir`) dereferences garbage and crashes.
// Keeping them in a regular file gives them lazy initialization that works in
// both the executable and the test bundle.

let defaultSecretsFile = ".hush"
let identityDir = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".hush", isDirectory: true)
let identityFile = identityDir.appendingPathComponent("identity.json")

/// When the MCP gateway is serving, stdout carries only JSON-RPC frames, so any
/// human-facing note must go to stderr instead (a stray stdout line corrupts the
/// protocol stream). `note(_:)` consults this.
var mcpStdoutGuard = false
