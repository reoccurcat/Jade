//
//  bad_queryApp.swift
//  bad_query
//
//  Created by Taj C on 8/10/26.
//

import SwiftUI
import Foundation
import Network
import Darwin

@main
struct bad_queryApp: App {
    @StateObject private var state = AppState()
    init() {
        // Local HTTP JSON API for driving the sandbox escape from the desktop
        // over USB (iproxy 8642 8642 <UDID>). No auth: the trust boundary is
        // the USB pairing itself. See JadeControl below.
        JadeControlServer.shared.start()
    }
    var body: some Scene {
        WindowGroup {
            BQRootView()
                .environmentObject(state)
                .overlay {
                    if state.show_respring {
                        RespringView()
                            .brightness(-1.0)
                            .ignoresSafeArea()
                    }
                }
        }
    }
}

// MARK: - JadeControl
//
// Minimal HTTP/1.1 + JSON server bound to 127.0.0.1:8642. Exists so a desktop
// tool can drive Jade's sandbox escape without hand-tapping the SwiftUI.
//
// Routes (all POST unless noted):
//   GET  /            — health probe
//   POST /ls          {path}                    → directory listing
//   POST /read        {path, offset?, length?}  → file bytes (base64)
//   POST /stat        {path}                    → lstat metadata
//   POST /find        {root, glob?, max_depth?, limit?} → BFS with substring filter
//   POST /gestalt/get {key?}                    → MobileGestalt read (key optional)
//   POST /apps/list                             → app enumeration via bundle dir
//
// Reachable only via USB port forward (iproxy). Sandbox-shared localhost.
// No writes — gestalt_set / file write / delete deliberately absent in v1.

final class JadeControlServer {
    static let shared = JadeControlServer()
    private var listener: NWListener?
    private let queue = DispatchQueue(label: "jade.control.server", qos: .userInitiated)

    private init() {}

    func start(port: UInt16 = 8642) {
        guard listener == nil else { return }
        guard let nwPort = NWEndpoint.Port(rawValue: port) else { return }
        do {
            let params = NWParameters.tcp
            params.allowLocalEndpointReuse = true
            let l = try NWListener(using: params, on: nwPort)
            l.newConnectionHandler = { [weak self] conn in
                self?.accept(conn)
            }
            l.start(queue: queue)
            self.listener = l
            NSLog("[jade-control] listening on 127.0.0.1:\(port)")
        } catch {
            NSLog("[jade-control] failed to start: \(error)")
        }
    }

    private func accept(_ conn: NWConnection) {
        conn.start(queue: queue)
        readRequest(conn: conn, buffer: Data())
    }

    private func readRequest(conn: NWConnection, buffer: Data) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isDone, _ in
            guard let self = self else { return }
            var buf = buffer
            if let d = data { buf.append(d) }

            guard let headerEnd = buf.range(of: Data("\r\n\r\n".utf8)) else {
                if isDone { conn.cancel(); return }
                self.readRequest(conn: conn, buffer: buf)
                return
            }

            let headerStr = String(data: buf.subdata(in: 0..<headerEnd.lowerBound), encoding: .utf8) ?? ""
            let lines = headerStr.components(separatedBy: "\r\n")
            let requestLine = lines.first ?? ""
            let parts = requestLine.split(separator: " ").map(String.init)
            guard parts.count >= 2 else {
                self.send(conn, status: 400, json: ["error": "malformed request line"])
                return
            }
            let method = parts[0]
            let path = parts[1]

            var contentLength = 0
            for line in lines.dropFirst() {
                if line.lowercased().hasPrefix("content-length:") {
                    let v = line.dropFirst("content-length:".count).trimmingCharacters(in: .whitespaces)
                    contentLength = Int(v) ?? 0
                }
            }

            let bodyStart = headerEnd.upperBound
            let bodyAvailable = buf.count - bodyStart
            if bodyAvailable < contentLength {
                if isDone { conn.cancel(); return }
                self.readRequest(conn: conn, buffer: buf)
                return
            }
            let body = contentLength > 0 ? buf.subdata(in: bodyStart..<(bodyStart + contentLength)) : Data()

            self.dispatch(method: method, path: path, body: body, conn: conn)
        }
    }

    private func dispatch(method: String, path: String, body: Data, conn: NWConnection) {
        let req: [String: Any] = (try? JSONSerialization.jsonObject(with: body) as? [String: Any]) ?? [:]
        let route = "\(method) \(path)"

        switch route {
        case "GET /", "GET /health":
            send(conn, status: 200, json: ["ok": true, "server": "jade-control", "version": 1])
        case "POST /ls":
            handleLs(req, conn: conn)
        case "POST /read":
            handleRead(req, conn: conn)
        case "POST /stat":
            handleStat(req, conn: conn)
        case "POST /find":
            handleFind(req, conn: conn)
        case "POST /gestalt/get":
            handleGestaltGet(req, conn: conn)
        case "POST /apps/list":
            handleAppsList(req, conn: conn)
        default:
            send(conn, status: 404, json: ["error": "no such route", "route": route])
        }
    }

    // MARK: Handlers

    private func handleLs(_ req: [String: Any], conn: NWConnection) {
        guard let path = req["path"] as? String, path.hasPrefix("/") else {
            send(conn, status: 400, json: ["error": "path required (absolute)"])
            return
        }
        let handle = openExtension(path: path)
        guard handle > 0 else {
            send(conn, status: 500, json: ["error": "bad_query failed", "code": Int(handle)])
            return
        }
        defer { bad_query_release(handle) }

        if let entries = try? FileManager.default.contentsOfDirectory(atPath: path) {
            let items: [[String: Any]] = entries.sorted().map { name in
                let full = (path as NSString).appendingPathComponent(name)
                var st = stat()
                let ok = lstat(full, &st) == 0
                return [
                    "name": name,
                    "type": ok ? Self.typeStr(mode: st.st_mode) : "unknown",
                    "size": ok ? Int64(st.st_size) : 0,
                    "mtime": ok ? Int64(st.st_mtimespec.tv_sec) : 0,
                ]
            }
            send(conn, status: 200, json: ["path": path, "count": items.count, "entries": items, "via": "fm"])
            return
        }

        // Fallback: inode scan through bad_query_list
        var cPath = path.utf8CString.map { Int8($0) }
        guard let cResult = bad_query_list(&cPath, 500_000) else {
            send(conn, status: 500, json: ["error": "bad_query_list returned null"])
            return
        }
        defer { free(cResult) }
        let listStr = String(cString: cResult)
        let paths = listStr.split(separator: "\n").map(String.init)
        send(conn, status: 200, json: ["path": path, "count": paths.count,
                                        "entries": paths.map { ["path": $0] as [String: Any] },
                                        "via": "inode"])
    }

    private func handleRead(_ req: [String: Any], conn: NWConnection) {
        guard let path = req["path"] as? String, path.hasPrefix("/") else {
            send(conn, status: 400, json: ["error": "path required"])
            return
        }
        let offset = (req["offset"] as? NSNumber)?.intValue ?? 0
        let length = (req["length"] as? NSNumber)?.intValue ?? (16 * 1024 * 1024)

        let handle = openExtension(path: path)
        guard handle > 0 else {
            send(conn, status: 500, json: ["error": "bad_query failed", "code": Int(handle)])
            return
        }
        defer { bad_query_release(handle) }

        let fd = open(path, O_RDONLY)
        guard fd >= 0 else {
            let e = errno
            send(conn, status: 500, json: ["error": "open failed", "errno": Int(e), "msg": String(cString: strerror(e))])
            return
        }
        defer { close(fd) }

        var st = stat()
        _ = fstat(fd, &st)
        let totalSize = Int64(st.st_size)

        _ = lseek(fd, off_t(offset), SEEK_SET)
        var buf = Data(count: length)
        let n = buf.withUnsafeMutableBytes { ptr -> Int in
            guard let base = ptr.baseAddress else { return 0 }
            return Darwin.read(fd, base, length)
        }
        if n < 0 {
            let e = errno
            send(conn, status: 500, json: ["error": "read failed", "errno": Int(e)])
            return
        }
        buf.count = n

        send(conn, status: 200, json: [
            "path": path,
            "total_size": totalSize,
            "offset": offset,
            "length": n,
            "eof": (offset + n) >= Int(totalSize),
            "data_b64": buf.base64EncodedString(),
        ])
    }

    private func handleStat(_ req: [String: Any], conn: NWConnection) {
        guard let path = req["path"] as? String, path.hasPrefix("/") else {
            send(conn, status: 400, json: ["error": "path required"])
            return
        }
        let handle = openExtension(path: path)
        guard handle > 0 else {
            send(conn, status: 500, json: ["error": "bad_query failed", "code": Int(handle)])
            return
        }
        defer { bad_query_release(handle) }

        var st = stat()
        guard lstat(path, &st) == 0 else {
            send(conn, status: 404, json: ["error": "lstat failed", "errno": Int(errno)])
            return
        }
        send(conn, status: 200, json: [
            "path": path,
            "type": Self.typeStr(mode: st.st_mode),
            "size": Int64(st.st_size),
            "mode": Int(st.st_mode),
            "uid": Int(st.st_uid),
            "gid": Int(st.st_gid),
            "mtime": Int64(st.st_mtimespec.tv_sec),
            "ctime": Int64(st.st_ctimespec.tv_sec),
        ])
    }

    private func handleFind(_ req: [String: Any], conn: NWConnection) {
        guard let root = req["root"] as? String, root.hasPrefix("/") else {
            send(conn, status: 400, json: ["error": "root required"])
            return
        }
        let maxDepth = (req["max_depth"] as? NSNumber)?.intValue ?? 6
        let glob = req["glob"] as? String
        let limit = (req["limit"] as? NSNumber)?.intValue ?? 10_000

        var results: [[String: Any]] = []
        var q: [(String, Int)] = [(root, 0)]
        var seen = Set<String>()
        var handles: [Int64] = []
        defer { handles.forEach { bad_query_release($0) } }

        while !q.isEmpty && results.count < limit {
            let (dir, depth) = q.removeFirst()
            if !seen.insert(dir).inserted { continue }

            let h = openExtension(path: dir)
            if h > 0 { handles.append(h) }

            guard let entries = try? FileManager.default.contentsOfDirectory(atPath: dir) else { continue }
            for name in entries {
                let full = (dir as NSString).appendingPathComponent(name)
                var st = stat()
                let ok = lstat(full, &st) == 0
                let matches = glob == nil || name.range(of: glob!, options: [.caseInsensitive]) != nil
                if matches {
                    results.append([
                        "path": full,
                        "type": ok ? Self.typeStr(mode: st.st_mode) : "unknown",
                        "size": ok ? Int64(st.st_size) : 0,
                    ])
                    if results.count >= limit { break }
                }
                if ok && (st.st_mode & S_IFMT) == S_IFDIR && depth < maxDepth {
                    q.append((full, depth + 1))
                }
            }
        }
        send(conn, status: 200, json: ["root": root, "count": results.count, "results": results])
    }

    private func handleGestaltGet(_ req: [String: Any], conn: NWConnection) {
        let mgDir = "/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache"
        let mgFile = "\(mgDir)/Library/Caches/com.apple.MobileGestalt.plist"

        // Use the same fallback chain as any other path. Jade's gestalt
        // model opens the SystemGroup root, then reads the plist through
        // the extension that grants — no gestalt-specific group required.
        let handle = openExtension(path: mgDir)
        guard handle > 0 else {
            send(conn, status: 500, json: ["error": "bad_query on gestalt group failed", "code": Int(handle)])
            return
        }
        defer { bad_query_release(handle) }

        guard let data = FileManager.default.contents(atPath: mgFile),
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else {
            send(conn, status: 500, json: ["error": "failed to read/parse MobileGestalt.plist"])
            return
        }

        let cacheExtra = plist["CacheExtra"] as? [String: Any]

        if let key = req["key"] as? String {
            var value: Any? = cacheExtra?[key]
            if value == nil { value = plist[key] }
            send(conn, status: 200, json: [
                "key": key,
                "value": Self.jsonSafe(value),
                "found": value != nil,
            ])
            return
        }

        // No key → summary: return CacheExtra key list (usually the queryable one)
        if let ce = cacheExtra {
            send(conn, status: 200, json: [
                "cache_extra_keys": Array(ce.keys).sorted(),
                "cache_extra_count": ce.count,
                "top_level_keys": Array(plist.keys).sorted(),
            ])
        } else {
            send(conn, status: 200, json: [
                "top_level_keys": Array(plist.keys).sorted(),
                "count": plist.count,
            ])
        }
    }

    private func handleAppsList(_ req: [String: Any], conn: NWConnection) {
        let bundlesDir = "/var/containers/Bundle/Application"
        let handle = openExtension(path: bundlesDir)
        guard handle > 0 else {
            send(conn, status: 500, json: ["error": "bad_query on bundles failed", "code": Int(handle)])
            return
        }
        defer { bad_query_release(handle) }

        var apps: [[String: Any]] = []
        if let uuids = try? FileManager.default.contentsOfDirectory(atPath: bundlesDir) {
            for uuid in uuids.sorted() {
                let dir = "\(bundlesDir)/\(uuid)"
                guard let contents = try? FileManager.default.contentsOfDirectory(atPath: dir) else { continue }
                guard let appName = contents.first(where: { $0.hasSuffix(".app") }) else { continue }
                let appPath = "\(dir)/\(appName)"
                let plistPath = "\(appPath)/Info.plist"
                var bundleId = ""
                var displayName = ""
                var version = ""
                if let d = try? Data(contentsOf: URL(fileURLWithPath: plistPath)),
                   let info = try? PropertyListSerialization.propertyList(from: d, format: nil) as? [String: Any] {
                    bundleId = info["CFBundleIdentifier"] as? String ?? ""
                    displayName = (info["CFBundleDisplayName"] as? String) ?? (info["CFBundleName"] as? String) ?? ""
                    version = (info["CFBundleShortVersionString"] as? String) ?? ""
                }
                apps.append([
                    "uuid": uuid,
                    "bundle_id": bundleId,
                    "display_name": displayName,
                    "version": version,
                    "path": appPath,
                ])
            }
        }
        send(conn, status: 200, json: ["count": apps.count, "apps": apps])
    }

    // MARK: Helpers

    // Mirror BQFileSystemModel.rawBadQuery: create:true skips a pre-flight
    // lstat() that would fail from the app's own sandbox (returning -254
    // before the extension is even attempted). On failure, fall back through
    // the app-group route — required for App Group containers on iOS 26 and
    // sometimes the only route that lands on Shared/SystemGroup paths too.
    private static let appGroupIdentifier = "group.com.jason.Jade"
    private func openExtension(path: String) -> Int64 {
        var cPath = path.utf8CString.map { Int8($0) }
        var handle = bad_query(&cPath, true, nil, false)
        if handle < 0 {
            var cGroup = Self.appGroupIdentifier.utf8CString.map { Int8($0) }
            handle = bad_query(&cPath, true, &cGroup, true)
            if handle < 0 {
                handle = bad_query(&cPath, true, &cGroup, false)
            }
        }
        return handle
    }

    private static func typeStr(mode: mode_t) -> String {
        switch mode & S_IFMT {
        case S_IFDIR:  return "dir"
        case S_IFREG:  return "file"
        case S_IFLNK:  return "symlink"
        case S_IFCHR:  return "char"
        case S_IFBLK:  return "block"
        case S_IFIFO:  return "fifo"
        case S_IFSOCK: return "socket"
        default:       return "unknown"
        }
    }

    private static func jsonSafe(_ v: Any?) -> Any {
        guard let v = v else { return NSNull() }
        if let s = v as? String { return s }
        if let n = v as? NSNumber { return n }
        if let b = v as? Bool { return b }
        if let d = v as? Data {
            return [
                "_type": "data",
                "size": d.count,
                "b64": d.base64EncodedString(),
            ] as [String: Any]
        }
        if let date = v as? Date {
            return ["_type": "date", "iso": ISO8601DateFormatter().string(from: date)] as [String: Any]
        }
        if let arr = v as? [Any] { return arr.map { jsonSafe($0) } }
        if let dict = v as? [String: Any] { return dict.mapValues { jsonSafe($0) } }
        return String(describing: v)
    }

    private func send(_ conn: NWConnection, status: Int, json: [String: Any]) {
        let body = (try? JSONSerialization.data(withJSONObject: json, options: [])) ?? Data("{}".utf8)
        let statusText: String
        switch status {
        case 200: statusText = "OK"
        case 400: statusText = "Bad Request"
        case 404: statusText = "Not Found"
        default:  statusText = "Error"
        }
        let header = "HTTP/1.1 \(status) \(statusText)\r\nContent-Type: application/json\r\nContent-Length: \(body.count)\r\nConnection: close\r\n\r\n"
        var response = Data(header.utf8)
        response.append(body)
        conn.send(content: response, completion: .contentProcessed { _ in
            conn.cancel()
        })
    }
}
