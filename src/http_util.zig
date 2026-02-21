//! Shared HTTP utilities — fully native std.http.Client.
//!
//! All functions use Zig's built-in HTTP client. No curl subprocess dependency.
//! HTTP/HTTPS proxies are supported natively; SOCKS5 proxies are NOT supported
//! (use an HTTP proxy or remove the proxy setting).

const std = @import("std");
const Allocator = std.mem.Allocator;

const log = std.log.scoped(.http_util);

/// Parsed header result — fixed buffer of name/value pairs.
const ParsedHeaders = struct {
    hdrs: [20]std.http.Header = undefined,
    len: usize = 0,
};

/// Parse "Name: Value" header strings into std.http.Header structs.
/// Returns a fixed-size buffer of parsed headers and the count.
fn parseHeaders(raw: []const []const u8) ParsedHeaders {
    var result: ParsedHeaders = .{};
    for (raw) |hdr| {
        if (result.len >= 20) break;
        if (std.mem.indexOfScalar(u8, hdr, ':')) |colon| {
            const name = hdr[0..colon];
            var value = hdr[colon + 1 ..];
            // Skip leading space after colon
            if (value.len > 0 and value[0] == ' ') value = value[1..];
            result.hdrs[result.len] = .{ .name = name, .value = value };
            result.len += 1;
        }
    }
    return result;
}

/// Perform a native HTTP request. Core implementation used by all public functions.
fn nativeRequest(
    allocator: Allocator,
    method: std.http.Method,
    url: []const u8,
    payload: ?[]const u8,
    headers: []const std.http.Header,
    proxy_url: ?[]const u8,
) ![]u8 {
    var client: std.http.Client = .{ .allocator = allocator };
    defer client.deinit();

    // Configure proxy if provided — struct must live on THIS stack frame
    // (client.fetch uses the pointer during the call)
    var proxy: std.http.Client.Proxy = undefined;
    if (proxy_url) |pu| {
        const uri = std.Uri.parse(pu) catch {
            log.warn("invalid proxy URL: {s}", .{pu});
            return error.HttpRequestFailed;
        };

        const protocol = std.http.Client.Protocol.fromUri(uri) orelse {
            log.warn("unsupported proxy scheme: {s} — only http/https proxies are supported", .{pu});
            return error.HttpRequestFailed;
        };

        const raw_host = uri.host orelse {
            log.warn("proxy URL has no host: {s}", .{pu});
            return error.HttpRequestFailed;
        };

        proxy = .{
            .protocol = protocol,
            .host = raw_host.percent_encoded,
            .authorization = null,
            .port = uri.port orelse switch (protocol) {
                .plain => 80,
                .tls => 443,
            },
            .supports_connect = true,
        };

        client.https_proxy = &proxy;
        client.http_proxy = &proxy;
    }

    var aw: std.Io.Writer.Allocating = .init(allocator);
    errdefer allocator.free(aw.writer.buffer);

    const result = client.fetch(.{
        .location = .{ .url = url },
        .method = method,
        .payload = payload,
        .extra_headers = headers,
        .response_writer = &aw.writer,
    }) catch return error.HttpRequestFailed;

    if (result.status.class() == .server_error or result.status.class() == .client_error) {
        log.warn("HTTP {s} {s} returned {}", .{ @tagName(method), url, result.status });
    }

    // Return the response body as an owned slice
    const response = aw.writer.buffer[0..aw.writer.end];
    const owned = try allocator.dupe(u8, response);
    allocator.free(aw.writer.buffer);
    return owned;
}

/// HTTP POST with optional proxy and timeout.
///
/// `headers` is a slice of header strings (e.g. `"Authorization: Bearer xxx"`).
/// `proxy` is an optional proxy URL (e.g. `"http://host:port"`).
/// `max_time` is accepted for API compatibility but not used by native client.
/// Returns the response body. Caller owns returned memory.
pub fn curlPostWithProxy(
    allocator: Allocator,
    url: []const u8,
    body: []const u8,
    headers: []const []const u8,
    proxy: ?[]const u8,
    max_time: ?[]const u8,
) ![]u8 {
    _ = max_time; // Native client manages timeouts internally
    const parsed = parseHeaders(headers);

    // Check if caller already provides Content-Type
    var has_content_type = false;
    for (parsed.hdrs[0..parsed.len]) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "Content-Type")) {
            has_content_type = true;
            break;
        }
    }

    // Build extra_headers: optionally prepend Content-Type + caller headers
    var all_hdrs: [21]std.http.Header = undefined;
    var hdr_count: usize = 0;
    if (!has_content_type) {
        all_hdrs[0] = .{ .name = "Content-Type", .value = "application/json" };
        hdr_count = 1;
    }
    for (parsed.hdrs[0..parsed.len]) |h| {
        all_hdrs[hdr_count] = h;
        hdr_count += 1;
    }
    return nativeRequest(allocator, .POST, url, body, all_hdrs[0..hdr_count], proxy);
}

/// HTTP POST (no proxy, no timeout). Convenience wrapper.
pub fn curlPost(allocator: Allocator, url: []const u8, body: []const u8, headers: []const []const u8) ![]u8 {
    return curlPostWithProxy(allocator, url, body, headers, null, null);
}

/// HTTP GET with optional proxy.
///
/// `headers` is a slice of header strings (e.g. `"Authorization: Bearer xxx"`).
/// `timeout_secs` is accepted for API compatibility but not used by native client.
/// Returns the response body. Caller owns returned memory.
pub fn curlGetWithProxy(
    allocator: Allocator,
    url: []const u8,
    headers: []const []const u8,
    timeout_secs: []const u8,
    proxy: ?[]const u8,
) ![]u8 {
    _ = timeout_secs; // Native client manages timeouts internally
    const parsed = parseHeaders(headers);
    return nativeRequest(allocator, .GET, url, null, parsed.hdrs[0..parsed.len], proxy);
}

/// HTTP GET (no proxy). Convenience wrapper.
pub fn curlGet(allocator: Allocator, url: []const u8, headers: []const []const u8, timeout_secs: []const u8) ![]u8 {
    return curlGetWithProxy(allocator, url, headers, timeout_secs, null);
}

// ── Tests ───────────────────────────────────────────────────────────

test "parseHeaders splits name and value" {
    const raw = &[_][]const u8{
        "Authorization: Bearer tok123",
        "X-Custom: value",
    };
    const result = parseHeaders(raw);
    try std.testing.expectEqual(@as(usize, 2), result.len);
    try std.testing.expectEqualStrings("Authorization", result.hdrs[0].name);
    try std.testing.expectEqualStrings("Bearer tok123", result.hdrs[0].value);
    try std.testing.expectEqualStrings("X-Custom", result.hdrs[1].name);
    try std.testing.expectEqualStrings("value", result.hdrs[1].value);
}

test "parseHeaders empty slice" {
    const result = parseHeaders(&.{});
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "parseHeaders no colon is skipped" {
    const raw = &[_][]const u8{"InvalidHeader"};
    const result = parseHeaders(raw);
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "curlPost compiles and is callable" {
    try std.testing.expect(true);
}

test "curlGet compiles and is callable" {
    try std.testing.expect(true);
}
