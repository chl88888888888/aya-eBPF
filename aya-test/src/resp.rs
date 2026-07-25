//! RESP protocol command classification.
//!
//! Extracts the Redis command name from raw bytes captured by the
//! eBPF probe.  Returns `Cow::Borrowed` for known commands (zero
//! allocation) and `Cow::Owned` otherwise (one allocation).

use std::borrow::Cow;

/// Decodes `req_data` (raw bytes from the eBPF probe) to extract the
/// Redis command name.
///
/// **Fast path** — byte scan for `$LEN\r\nCMD\r\n`, then a flat match
/// against ~35 common Redis commands → `Cow::Borrowed` (zero alloc).
///
/// **Slow path** — uppercase on stack + one heap allocation.  Also
/// falls back to `resp-rs` for edge-case RESP payloads.
pub fn classify_command(req_data: &[u8; 32]) -> Cow<'static, str> {
    let end = req_data.iter().position(|&b| b == 0).unwrap_or(32);
    let data = &req_data[..end];
    if data.len() < 4 {
        return Cow::Borrowed("OTHER");
    }

    // ── Fast path: lightweight RESP scan ─────────────────────────
    if let Some(cmd) = scan_resp_command(data) {
        return cmd;
    }

    // ── Fallback: full resp-rs decode ───────────────────────────
    use std::io::BufReader;
    let mut decoder = resp::Decoder::new(BufReader::new(data));
    if let Ok(resp::Value::Array(ref values)) = decoder.decode() {
        if !values.is_empty() {
            if let resp::Value::Bulk(ref cmd) = values[0] {
                return Cow::Owned(cmd.to_uppercase());
            }
        }
    }

    Cow::Borrowed("OTHER")
}

/// Scans for `$LEN\r\nCMD\r\n`.  If CMD is a known uppercase command,
/// returns `Cow::Borrowed`; otherwise uppercases and allocates.
fn scan_resp_command(data: &[u8]) -> Option<Cow<'static, str>> {
    for (i, _) in data.iter().enumerate().filter(|(_, b)| **b == b'$') {
        let start = i + 1;
        let digit_end = data[start..]
            .iter()
            .position(|b| !b.is_ascii_digit())
            .map(|p| start + p)
            .unwrap_or(data.len());

        if digit_end > start
            && digit_end + 1 < data.len()
            && data[digit_end] == b'\r'
            && data[digit_end + 1] == b'\n'
        {
            let len_str = std::str::from_utf8(&data[start..digit_end]).ok()?;
            let len: usize = len_str.parse().ok()?;
            let cmd_start = digit_end + 2;
            let cmd_end = (cmd_start + len).min(data.len());

            if cmd_end > cmd_start {
                let bytes = &data[cmd_start..cmd_end];
                if !bytes.iter().all(|b| b.is_ascii_alphabetic()) {
                    continue;
                }
                // Fast: try to match against known uppercase commands.
                if let Some(s) = try_static(bytes) {
                    return Some(Cow::Borrowed(s));
                }
                // Otherwise uppercase on stack, allocate once.
                let mut v = bytes.to_vec();
                v.make_ascii_uppercase();
                return Some(Cow::Owned(String::from_utf8(v).ok()?));
            }
        }
    }
    None
}

/// Flat byte-match against ~35 common Redis commands.
/// Compiler lowers this to an efficient jump table / decision tree.
fn try_static(bytes: &[u8]) -> Option<&'static str> {
    Some(match bytes {
        // 3-byte
        b"GET" => "GET",   b"SET" => "SET",   b"DEL" => "DEL",
        // 4-byte
        b"INCR" => "INCR", b"DECR" => "DECR", b"HGET" => "HGET",
        b"HSET" => "HSET", b"PING" => "PING", b"INFO" => "INFO",
        b"MGET" => "MGET", b"MSET" => "MSET", b"KEYS" => "KEYS",
        b"TYPE" => "TYPE", b"SCAN" => "SCAN", b"QUIT" => "QUIT",
        b"AUTH" => "AUTH", b"ECHO" => "ECHO", b"EXEC" => "EXEC",
        b"MULT" => "MULT", b"LPOP" => "LPOP", b"RPOP" => "RPOP",
        b"LLEN" => "LLEN", b"XADD" => "XADD", b"ZADD" => "ZADD",
        b"HDEL" => "HDEL", b"HLEN" => "HLEN", b"SADD" => "SADD",
        b"SPOP" => "SPOP",
        // 5-byte
        b"LPUSH" => "LPUSH", b"RPUSH" => "RPUSH", b"SETNX" => "SETNX",
        b"SETEX" => "SETEX", b"WATCH" => "WATCH", b"XREAD" => "XREAD",
        // 6-byte
        b"PUBLISH" => "PUBLISH", b"SELECT" => "SELECT",
        b"RENAME" => "RENAME",   b"EXPIRE" => "EXPIRE",
        b"APPEND" => "APPEND",   b"STRLEN" => "STRLEN",
        b"UNLINK" => "UNLINK",   b"GETSET" => "GETSET",
        // 7-byte
        b"GETRANGE" => "GETRANGE",
        _ => return None,
    })
}
