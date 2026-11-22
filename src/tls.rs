// Copyright 2025 Dillution <hskimse1@gmail.com>.
//
// This file is part of DPIBreak.
//
// DPIBreak is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// DPIBreak is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
// for more details.
//
// You should have received a copy of the GNU General Public License
// along with DPIBreak. If not, see <https://www.gnu.org/licenses/>.

fn bytes_to_usize(bytes: &[u8], size: usize) -> Option<usize> {
    Some(match size {
        1 => bytes[0] as usize,
        2 => u16::from_be_bytes(bytes.try_into().ok()?) as usize,
        3 => ((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | (bytes[2] as usize),
        4 => u32::from_be_bytes(bytes.try_into().ok()?) as usize,
        8 => u64::from_be_bytes(bytes.try_into().ok()?) as usize,
        _ => return None,
    })
}

struct TLSMsg<'a> {
    ptr: usize,
    payload: &'a [u8],
}

impl<'a> TLSMsg<'a> {
    fn new(payload: &'a [u8]) -> Self {
        Self { ptr: 0, payload }
    }

    fn pass(&mut self, size: usize) {
        self.ptr += size;
    }

    fn get_bytes(&mut self, size: usize) -> Option<&'a [u8]> {
        if size == 0 || self.ptr + size > self.payload.len() {
            return None;
        }

        let end = self.ptr + size;
        let ret = &self.payload[self.ptr..end];
        self.ptr = end;
        Some(ret)
    }

    fn get_uint(&mut self, size: usize) -> Option<usize> {
        bytes_to_usize(self.get_bytes(size)?, size)
    }

    fn get_ptr(&self) -> usize {
        self.ptr
    }
}

pub fn is_client_hello(payload: &[u8]) -> bool {
    let mut record = TLSMsg::new(payload);
    if record.get_uint(1) != Some(22) {
        // type
        return false; // not handshake
    }

    record.pass(2); // legacy_record_version
    record.pass(2); // length

    if record.get_ptr() >= payload.len() {
        return false;
    }

    let fragment = &record.payload[record.get_ptr()..]; // fragment
    if TLSMsg::new(fragment).get_uint(1) != Some(1) {
        // msg_type
        return false; // not clienthello
    }

    true
}

/// Extract the server_name (SNI) host from a TLS ClientHello record.
///
/// Returns `None` if the payload is not a ClientHello, carries no SNI
/// extension, or is truncated before it.
pub fn sni(payload: &[u8]) -> Option<&str> {
    let mut msg = TLSMsg::new(payload);

    // TLSPlaintext
    if msg.get_uint(1)? != 22 {
        return None; // not handshake
    }
    msg.pass(2); // legacy_record_version
    msg.pass(2); // length

    // Handshake
    if msg.get_uint(1)? != 1 {
        return None; // not clienthello
    }
    msg.pass(3); // length

    // ClientHello
    msg.pass(2); // legacy_version
    msg.pass(32); // random
    let session_id_len = msg.get_uint(1)?;
    msg.pass(session_id_len);
    let cipher_suites_len = msg.get_uint(2)?;
    msg.pass(cipher_suites_len);
    let compression_len = msg.get_uint(1)?;
    msg.pass(compression_len);

    let extensions_len = msg.get_uint(2)?;
    let extensions_end = msg
        .get_ptr()
        .saturating_add(extensions_len)
        .min(payload.len());

    while msg.get_ptr() + 4 <= extensions_end {
        let ext_type = msg.get_uint(2)?;
        let ext_len = msg.get_uint(2)?;

        if ext_type != 0 {
            msg.pass(ext_len);
            continue;
        }

        // ServerNameList
        let mut list = TLSMsg::new(msg.get_bytes(ext_len)?);
        list.pass(2); // server_name_list length
        if list.get_uint(1)? != 0 {
            return None; // name_type != host_name
        }
        let name_len = list.get_uint(2)?;
        return std::str::from_utf8(list.get_bytes(name_len)?).ok();
    }

    None
}

/// Match `host` against a domain `pattern` (case-insensitive, trailing
/// dot ignored).
///
/// - `example.com` matches only `example.com`.
/// - `*.example.com` matches any subdomain of `example.com`, but not
///   `example.com` itself.
pub fn domain_matches(pattern: &str, host: &str) -> bool {
    // Compare as bytes: SNI comes from the wire and slicing a &str at a
    // non-char boundary would panic.
    let host = host.trim_end_matches('.').as_bytes();
    let pattern = pattern.trim_end_matches('.').as_bytes();

    match pattern.strip_prefix(b"*.") {
        Some(suffix) => {
            let split = host.len().wrapping_sub(suffix.len());
            host.len() > suffix.len() + 1
                && host[split..].eq_ignore_ascii_case(suffix)
                && host[split - 1] == b'.'
        }
        None => host.eq_ignore_ascii_case(pattern),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal ClientHello record with the given SNI host.
    fn client_hello(host: Option<&str>) -> Vec<u8> {
        let mut exts = Vec::new();
        // a dummy extension before SNI (supported_versions)
        exts.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);
        if let Some(h) = host {
            let h = h.as_bytes();
            let name_len = h.len() as u16;
            let list_len = name_len + 3;
            let ext_len = list_len + 2;
            exts.extend_from_slice(&[0x00, 0x00]);
            exts.extend_from_slice(&ext_len.to_be_bytes());
            exts.extend_from_slice(&list_len.to_be_bytes());
            exts.push(0x00);
            exts.extend_from_slice(&name_len.to_be_bytes());
            exts.extend_from_slice(h);
        }

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version
        body.extend_from_slice(&[0xab; 32]); // random
        body.push(32); // session_id
        body.extend_from_slice(&[0xcd; 32]);
        body.extend_from_slice(&[0x00, 0x04, 0x13, 0x01, 0x13, 0x02]); // cipher suites
        body.extend_from_slice(&[0x01, 0x00]); // compression
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut hs = vec![0x01];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);

        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn sni_extracts_host() {
        let ch = client_hello(Some("www.example.com"));
        assert!(is_client_hello(&ch));
        assert_eq!(sni(&ch), Some("www.example.com"));
    }

    #[test]
    fn sni_missing_or_truncated() {
        assert_eq!(sni(&client_hello(None)), None);

        let ch = client_hello(Some("www.example.com"));
        for cut in [0, 1, 5, 6, 43, 76, ch.len() - 1] {
            assert_eq!(sni(&ch[..cut]), None, "cut at {cut}");
        }
    }

    #[test]
    fn sni_not_clienthello() {
        let mut ch = client_hello(Some("a.b"));
        ch[5] = 0x02; // ServerHello
        assert_eq!(sni(&ch), None);
    }

    #[test]
    fn domain_matching() {
        assert!(domain_matches("example.com", "example.com"));
        assert!(domain_matches("example.com", "EXAMPLE.com."));
        assert!(!domain_matches("example.com", "www.example.com"));

        assert!(domain_matches("*.example.com", "www.example.com"));
        assert!(domain_matches("*.example.com", "a.b.example.com"));
        assert!(!domain_matches("*.example.com", "example.com"));
        assert!(!domain_matches("*.example.com", "badexample.com"));
        assert!(!domain_matches("*.example.com", ".example.com"));
    }
}
