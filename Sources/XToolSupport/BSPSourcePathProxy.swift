import Foundation
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif
import PackLib
import Subprocess
import SystemPackage
import XUtils

/// Request ids seen so far, so a response can be attributed to its method.
private final class IDTable: @unchecked Sendable {
    private let lock = NSLock()
    private var methods: [String: String] = [:]

    func set(_ id: Any, method: String) {
        lock.lock()
        defer { lock.unlock() }
        methods[Self.normalize(id)] = method
    }

    func method(for id: Any) -> String? {
        lock.lock()
        defer { lock.unlock() }
        return methods[Self.normalize(id)]
    }

    func remove(_ id: Any) {
        lock.lock()
        defer { lock.unlock() }
        methods.removeValue(forKey: Self.normalize(id))
    }

    private static func normalize(_ id: Any) -> String {
        switch id {
        case let n as NSNumber: return "n:\(n)"
        case let s as String: return "s:\(s)"
        default: return "\(id)"
        }
    }
}

/// Pipe between an LSP client and SwiftPM's `experimental-build-server` that
/// rewrites `buildTarget/sources` entries to their real (symlink-resolved) paths.
///
/// The xtool adapter references project sources through symlinks
/// (`Sources/<Target>/iOS -> ../../../iOS`) because SwiftPM rejects target paths
/// outside the package root. SwiftPM therefore reports those sources under the
/// symlinked adapter path, while an editor opens the real file in the project
/// tree; sourcekit-lsp only follows a symlink in one direction (opened document
/// -> its own symlink target), so real-path documents find no build settings.
/// Resolving the symlinks on the build server side makes the reported sources
/// match whichever path the editor opened: the real path directly, and the
/// adapter path through sourcekit-lsp's own symlink fallback.
///
/// The rewrite is made bidirectional: URIs the client sends back
/// (`textDocument/sourceKitOptions`, `workspace/didChangeWatchedFiles`) are
/// mapped from real path to the symlink path SwiftPM registered, and paths in
/// sourceKitOptions responses (compiler args) are mapped symlink -> real so the
/// whole compile and the index stay in real-path space.
struct BSPSourcePathProxy {
    static var rewritingDisabled: Bool {
        ProcessInfo.processInfo.environment["XTOOL_BSP_NO_REWRITE"] != nil
    }

    func run(_ invocation: Subprocess.Configuration) async throws {
        let wireLog = WireLog()
        var outPipe: [Int32] = [0, 0]
        guard pipe(&outPipe) == 0 else {
            throw Console.Error("BSP proxy: pipe() failed")
        }
        let (outReadFd, outWriteFd) = (outPipe[0], outPipe[1])
        defer {
            close(outReadFd)
            close(outWriteFd)
        }
        // The child's stdout is pumped through a raw pipe with POSIX reads:
        // Subprocess's `.sequence` (AsyncBuffers) and Foundation FileHandle
        // reads both consume bytes on this Linux toolchain without ever
        // delivering them.
        let result = try await Subprocess.run(
            invocation,
            input: .inputWriter,
            output: .fileDescriptor(FileDescriptor(rawValue: outWriteFd), closeAfterSpawningProcess: false),
            error: .currentStandardError,
        ) { execution in
            let stdin = execution.standardInputWriter
            let ids = IDTable()
            let map = BSPPathMap()
            let output = FileHandle.standardOutput

            let outTask = Task.detached {
                var parser = LSPFrameParser()
                while true {
                    guard let chunk = Self.readChunk(fd: outReadFd) else { break }
                    parser.feed(chunk)
                    for frame in parser.popFrames() {
                        Self.handleServerFrame(frame, ids: ids, map: map, wireLog: wireLog, output: output)
                    }
                }
            }

            // client -> child, rewriting real paths back to the symlink paths
            // SwiftPM registered, and remembering request ids so a response can
            // be attributed to the method that produced it. Raw POSIX read:
            // Foundation's FileHandle.readData consumes bytes on Linux without
            // ever returning them.
            var clientParser = LSPFrameParser()
            while true {
                guard let chunk = Self.readChunk(fd: 0) else { break }
                clientParser.feed(chunk)
                for frame in clientParser.popFrames() {
                    let forwarded = Self.handleClientFrame(frame, map: map)
                    if let obj = (forwarded ?? frame).parsedObject, let id = obj["id"], let method = obj["method"] as? String {
                        ids.set(id, method: method)
                    }
                    let outFrame = forwarded ?? frame
                    wireLog.write("C>S", outFrame.parsedObject ?? ["_raw": "\(outFrame.count) bytes"])
                    // the frame is the bare JSON body: re-add the LSP header
                    // the parser stripped, or the child sees no message at all
                    var framed = Data("Content-Length: \(outFrame.count)\r\n\r\n".utf8)
                    framed.append(contentsOf: outFrame)
                    _ = try await stdin.write([UInt8](framed))
                }
            }
            try await stdin.finish()
            _ = await outTask.result
        }
        try result.checkSuccess()
    }

    private static func handleServerFrame(
        _ frame: [UInt8],
        ids: IDTable,
        map: BSPPathMap,
        wireLog: WireLog,
        output: FileHandle
    ) {
        guard let obj = frame.parsedObject else {
            wireLog.write("S>C", ["_raw": "\(frame.count) bytes"])
            try? sendRaw(frame, to: output)  // not JSON we understand: forward untouched
            return
        }
        var out = obj
        if let method = obj["method"] as? String {
            if let id = obj["id"] {
                ids.set(id, method: method)
            }
            if method == "buildTarget/sources", !rewritingDisabled {
                out = rewriteSources(obj, map: map) ?? obj
            }
        } else if let id = obj["id"], let method = ids.method(for: id) {
            if method == "buildTarget/sources", !rewritingDisabled {
                out = rewriteSources(obj, map: map) ?? obj
            } else if method == "buildTarget/sourceKitOptions" || method == "textDocument/sourceKitOptions",
                      !rewritingDisabled {
                if let result = obj["result"] {
                    out["result"] = rewritePathStrings(result, map: map)
                }
            }
        }
        if let id = obj["id"] {
            ids.remove(id)
        }
        wireLog.write("S>C", out)
        do {
            try send(out, to: output)
        } catch {
            FileHandle.standardError.write(Data("PROXY: send failed: \(error)\n".utf8))
        }
    }

    /// Maps URIs the client sends back into the path space SwiftPM registered.
    /// Returns the frame to forward, or nil to forward `frame` untouched.
    private static func handleClientFrame(_ frame: [UInt8], map: BSPPathMap) -> [UInt8]? {
        guard !rewritingDisabled else { return nil }
        guard let obj = frame.parsedObject, let method = obj["method"] as? String else { return nil }
        switch method {
        case "textDocument/sourceKitOptions":
            guard let params = obj["params"] as? [String: Any],
                  let textDocument = params["textDocument"] as? [String: Any],
                  let uri = textDocument["uri"] as? String,
                  let path = URL(string: uri)?.path,
                  let symlinkURI = map.symlinkURI(forRealPath: path)
            else { return nil }
            return substituteURIs(Data(frame), pairs: [(uri, symlinkURI)])
        case "workspace/didChangeWatchedFiles":
            guard let params = obj["params"] as? [String: Any],
                  let changes = params["changes"] as? [[String: Any]]
            else { return nil }
            var pairs: [(String, String)] = []
            for change in changes {
                guard let uri = change["uri"] as? String,
                      let path = URL(string: uri)?.path,
                      let symlinkURI = map.symlinkURI(forRealPath: path)
                else { continue }
                pairs.append((uri, symlinkURI))
            }
            return pairs.isEmpty ? nil : substituteURIs(Data(frame), pairs: pairs)
        default:
            return nil
        }
    }

    /// Swaps URI strings by byte-level substitution in the original frame.
    /// SwiftPM 6.4's sourceKitOptions lookup fails on any re-serialized request
    /// ("Found multiple indexing informations for the same source file") even
    /// when the logical content is byte-verified identical, so the frame's own
    /// bytes are kept: only the URI text is swapped (both JSON spellings, plain
    /// and `\/`-escaped; percent-escapes survive because the parsed string is
    /// byte-identical to what the client wrote) and the length recomputed.
    private static func substituteURIs(_ frame: Data, pairs: [(old: String, new: String)]) -> [UInt8]? {
        var out = String(decoding: frame, as: UTF8.self)
        for (old, new) in pairs {
            let plain = jsonEscape(old)
            let replacement = jsonEscape(new)
            guard plain != replacement else { continue }
            if out.contains(plain) {
                out = out.replacingOccurrences(of: plain, with: replacement)
                continue
            }
            // the client may have escaped the forward slashes
            let slashed = plain.replacingOccurrences(of: "/", with: "\\/")
            let slashedReplacement = replacement.replacingOccurrences(of: "/", with: "\\/")
            guard out.contains(slashed) else { return nil }
            out = out.replacingOccurrences(of: slashed, with: slashedReplacement)
        }
        return [UInt8](out.utf8)
    }

    /// The exact escape a JSONSerialization writer applies inside a string
    /// (`.withoutEscapingSlashes`).
    private static func jsonEscape(_ s: String) -> String {
        var out = ""
        for scalar in s.unicodeScalars {
            switch scalar {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            default:
                if scalar.value < 0x20 {
                    out += String(format: "\\u%04x", scalar.value)
                } else {
                    out.unicodeScalars.append(scalar)
                }
            }
        }
        return out
    }

    /// Rewrites every file URI in a `buildTarget/sources` result to its
    /// symlink-resolved real path, recording each pair for the reverse mapping.
    private static func rewriteSources(_ message: [String: Any], map: BSPPathMap) -> [String: Any]? {
        guard let result = message["result"] as? [String: Any],
              var items = result["items"] as? [[String: Any]]
        else { return nil }
        var changed = false
        for (i, itemIn) in items.enumerated() {
            var item = itemIn
            guard var sources = item["sources"] as? [[String: Any]] else { continue }
            for (j, var source) in sources.enumerated() {
                guard let uri = source["uri"] as? String, let resolved = resolvedURI(uri) else { continue }
                map.record(symlinkURI: uri, realURI: resolved)
                source["uri"] = resolved
                sources[j] = source
                changed = true
            }
            item["sources"] = sources
            items[i] = item
        }
        guard changed else { return nil }
        var out = message
        out["result"] = ["items": items]
        return out
    }

    /// Recursively applies the symlink -> real path replacement to every string
    /// in a JSON value (compiler args, working directories, ...).
    private static func rewritePathStrings(_ value: Any, map: BSPPathMap) -> Any {
        switch value {
        case var dict as [String: Any]:
            for (key, element) in dict {
                dict[key] = rewritePathStrings(element, map: map)
            }
            return dict
        case var array as [Any]:
            for i in array.indices {
                array[i] = rewritePathStrings(array[i], map: map)
            }
            return array
        case let string as String:
            return map.resolvePathReferences(string)
        default:
            return value
        }
    }

    /// `file:///a/b` -> `file://<symlink-resolved path>`, or nil when the path is
    /// not a file URL or resolving it changes nothing.
    static func resolvedURI(_ uri: String) -> String? {
        guard uri.hasPrefix("file://") else { return nil }
        guard let path = URL(string: uri)?.path else { return nil }
        let resolved = URL(fileURLWithPath: path).resolvingSymlinksInPath().path
        guard resolved != path else { return nil }
        var out = resolved
        if path.hasSuffix("/") && !resolved.hasSuffix("/") {
            out += "/"
        }
        return URL(fileURLWithPath: out).absoluteString
    }

    /// One chunk from a blocking file descriptor. nil on EOF or error.
    private static func readChunk(fd: Int32, max: Int = 64 * 1024) -> [UInt8]? {
        var buf = [UInt8](repeating: 0, count: max)
        let n = buf.withUnsafeMutableBytes {
            $0.withMemoryRebound(to: CChar.self) { read(fd, $0.baseAddress, max) }
        }
        if n > 0 { return Array(buf[0..<n]) }
        if n < 0, errno == EINTR { return readChunk(fd: fd, max: max) }
        return nil
    }

    private static func send(_ obj: [String: Any], to handle: FileHandle) throws {
        // .withoutEscapingSlashes: SwiftPM's BSP JSON parser mis-handles "\/"
        // (a re-encoded textDocument uri reaches it as a different path)
        let data = try JSONSerialization.data(withJSONObject: obj, options: [.withoutEscapingSlashes])
        try writeAll(Data("Content-Length: \(data.count)\r\n\r\n".utf8))
        try writeAll(data)
    }

    private static func sendRaw(_ frame: [UInt8], to handle: FileHandle) throws {
        try writeAll(Data("Content-Length: \(frame.count)\r\n\r\n".utf8))
        try writeAll(Data(frame))
    }

    /// POSIX write of the whole buffer to stdout. Foundation FileHandle writes
    /// to pipes are unreliable on this Linux toolchain.
    private static func writeAll(_ bytes: Data) throws {
        var offset = 0
        while offset < bytes.count {
            let n = bytes.withUnsafeBytes { write(1, $0.baseAddress!.advanced(by: offset), bytes.count - offset) }
            if n < 0 {
                if errno == EINTR { continue }
                throw Console.Error("BSP proxy: stdout write failed (errno \(errno))")
            }
            offset += n
        }
    }
}

/// Bidirectional map between the symlink paths SwiftPM reports and the real
/// paths the editor uses, built from the `buildTarget/sources` rewrite.
final class BSPPathMap: @unchecked Sendable {
    private let lock = NSLock()
    /// decoded real path -> the exact URI string SwiftPM reported
    private var realToSymlinkURI: [String: String] = [:]
    /// decoded symlink path -> decoded real path
    private var symlinkToRealPath: [String: String] = [:]

    func record(symlinkURI: String, realURI: String) {
        guard let symlinkPath = URL(string: symlinkURI)?.path,
              let realPath = URL(string: realURI)?.path
        else { return }
        lock.lock()
        defer { lock.unlock() }
        realToSymlinkURI[realPath] = symlinkURI
        symlinkToRealPath[symlinkPath] = realPath
    }

    func symlinkURI(forRealPath path: String) -> String? {
        lock.lock()
        defer { lock.unlock() }
        return realToSymlinkURI[path]
    }

    func resolvePathReferences(_ string: String) -> String {
        lock.lock()
        let pairs = symlinkToRealPath
        lock.unlock()
        guard !pairs.isEmpty, !string.isEmpty else { return string }
        var out = string
        // longest path first so a directory prefix cannot shadow its children
        for (symlink, real) in pairs.sorted(by: { $0.key.count > $1.key.count }) where out.contains(symlink) {
            out = out.replacingOccurrences(of: symlink, with: real)
        }
        return out
    }
}

/// Appends one JSON line per frame (both directions, truncated) so proxy
/// traffic can be inspected after a run. Path: `$XTOOL_BSP_WIRE_LOG` or
/// `~/lsp/proxy-wire-<pid>.log`. Missing directory or file: logging disabled.
final class WireLog: @unchecked Sendable {
    private let lock = NSLock()
    private let handle: FileHandle?

    init() {
        let env = ProcessInfo.processInfo.environment
        let path = env["XTOOL_BSP_WIRE_LOG"]
            ?? env["HOME"].map { "\($0)/lsp/proxy-wire-\(ProcessInfo.processInfo.processIdentifier).log" }
        guard let path else {
            handle = nil
            return
        }
        try? FileManager.default.createDirectory(
            atPath: (path as NSString).deletingLastPathComponent,
            withIntermediateDirectories: true
        )
        FileManager.default.createFile(atPath: path, contents: nil)
        handle = FileHandle(forWritingAtPath: path)
    }

    func write(_ direction: String, _ message: [String: Any]) {
        guard let handle else { return }
        let method = message["method"] as? String
        let record: [String: Any] = [
            "t": String(format: "%.3f", Date().timeIntervalSince1970),
            "dir": direction,
            "method": method ?? "<response>",
            "frame": Self.truncated(message),
        ]
        guard let line = try? JSONSerialization.data(withJSONObject: record) else { return }
        lock.lock()
        defer { lock.unlock() }
        try? handle.write(contentsOf: line + Data("\n".utf8))
    }

    private static func truncated(_ message: [String: Any]) -> String {
        guard var data = try? JSONSerialization.data(withJSONObject: message) else { return "<unserializable>" }
        let cap = 20_000
        guard data.count > cap else { return String(data: data, encoding: .utf8) ?? "<binary>" }
        data = data.prefix(cap) + Data("…<truncated>".utf8)
        return String(data: data, encoding: .utf8) ?? "<binary>"
    }
}

extension Array where Element == UInt8 {
    var parsedObject: [String: Any]? {
        (try? JSONSerialization.jsonObject(with: Data(self))) as? [String: Any]
    }
}

/// Incremental parser for `Content-Length`-framed JSON-RPC byte streams.
struct LSPFrameParser {
    private var buffer: [UInt8] = []

    mutating func feed(_ bytes: [UInt8]) {
        buffer.append(contentsOf: bytes)
    }

    mutating func popFrames() -> [[UInt8]] {
        var frames: [[UInt8]] = []
        while let headerEnd = findHeaderEnd() {
            let headerData = Data(buffer[0..<headerEnd])
            guard let header = String(data: headerData, encoding: .ascii),
                  let line = header.split(separator: "\r\n", omittingEmptySubsequences: false)
                      .last(where: { $0.lowercased().hasPrefix("content-length:") }),
                  let length = Int(line.split(separator: ":")[1].trimmingCharacters(in: .whitespaces))
            else {
                // Malformed header: drop what we have rather than desync forever.
                buffer.removeAll(keepingCapacity: false)
                return frames
            }
            let bodyStart = headerEnd + 4
            guard buffer.count >= bodyStart + length else { break }
            frames.append(Array(buffer[bodyStart..<bodyStart + length]))
            buffer.removeSubrange(0..<bodyStart + length)
        }
        return frames
    }

    private func findHeaderEnd() -> Int? {
        let separator: [UInt8] = [13, 10, 13, 10]  // \r\n\r\n
        guard separator.count <= buffer.count else { return nil }
        for i in 0...(buffer.count - separator.count) {
            if buffer[i] == 13, Array(buffer[i..<i + separator.count]) == separator {
                return i
            }
        }
        return nil
    }
}
