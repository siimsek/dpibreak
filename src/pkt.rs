// Copyright 2025-2026 Dillution <hskimse1@gmail.com>.
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

use anyhow::Result;
use anyhow::anyhow;
use etherparse::{IpSlice, TcpSlice};

use crate::opt;
use crate::platform;
use crate::tls;

mod fake;
mod hoptab;

struct PktView<'a> {
    ip: IpSlice<'a>,
    tcp: TcpSlice<'a>,
}

impl<'a> PktView<'a> {
    #[inline]
    fn from_raw(raw: &'a [u8]) -> Result<Self> {
        let ip = IpSlice::from_slice(raw)?;
        let tcp = TcpSlice::from_slice(ip.payload().payload)?;

        Ok(Self { ip, tcp })
    }

    #[inline]
    fn ttl(&self) -> u8 {
        use etherparse::IpSlice;

        match &self.ip {
            IpSlice::Ipv4(v4) => v4.header().ttl(),
            IpSlice::Ipv6(v6) => v6.header().hop_limit(),
        }
    }

    #[inline]
    fn saddr(&self) -> std::net::IpAddr {
        self.ip.source_addr()
    }

    #[inline]
    fn daddr(&self) -> std::net::IpAddr {
        self.ip.destination_addr()
    }
}

/// Write TCP/IP packet (payload = view.tcp.payload[start..Some(end)])
/// to out_buf, explicitly clearing before.
///
/// If payload, ttl or tcp_checksum is given, override view's one.
fn build_packet(
    view: &PktView,
    start: u32,
    end: Option<u32>,
    out_buf: &mut Vec<u8>,
    payload: Option<&[u8]>,
    ttl: Option<u8>,
    tcp_checksum: Option<u16>,
) -> Result<()> {
    use etherparse::*;

    let ip = &view.ip;
    let tcp = &view.tcp;
    let payload = payload.unwrap_or(tcp.payload());

    let end = end.unwrap_or(payload.len().try_into()?);

    if start > end || payload.len() < end as usize {
        return Err(anyhow!("invalid index"));
    }

    let opts = tcp.options();
    let mut tcp_hdr = tcp.to_header();
    tcp_hdr.sequence_number += start;

    let (builder, l3_len) = match ip {
        IpSlice::Ipv4(hdr) => {
            let mut ip_hdr = hdr.header().to_header();
            if let Some(t) = ttl {
                ip_hdr.time_to_live = t;
            };

            let exts = hdr.extensions().to_header();
            let l3_len = ip_hdr.header_len() + exts.header_len();

            (
                PacketBuilder::ip(IpHeaders::Ipv4(ip_hdr, hdr.extensions().to_header())),
                l3_len,
            )
        }

        IpSlice::Ipv6(hdr) => {
            let mut ip6_hdr = hdr.header().to_header();
            if let Some(t) = ttl {
                ip6_hdr.hop_limit = t;
            };

            let l3_len = Ipv6Header::LEN;

            (
                PacketBuilder::ip(IpHeaders::Ipv6(ip6_hdr, Default::default())),
                l3_len,
            )
        }
    };

    let builder = builder.tcp_header(tcp_hdr).options_raw(opts)?;

    let payload = &payload[start as usize..end as usize];

    out_buf.clear();
    builder.write(out_buf, payload)?;

    if let Some(cs) = tcp_checksum {
        let tcp_csum_off = l3_len + 16;

        if out_buf.len() < tcp_csum_off + 2 {
            return Err(anyhow!("packet too short for tcp checksum patch"));
        }
        out_buf[tcp_csum_off..tcp_csum_off + 2].copy_from_slice(&cs.to_be_bytes());
    }

    Ok(())
}

fn build_segment(
    view: &PktView,
    start: u32,
    end: Option<u32>,
    out_buf: &mut Vec<u8>,
) -> Result<()> {
    build_packet(view, start, end, out_buf, None, None, None)
}

fn send_segment(view: &PktView, start: u32, end: Option<u32>, buf: &mut Vec<u8>) -> Result<()> {
    use platform::send_to_raw;

    if opt::fake() && fake::fake_clienthello(view, start, end, buf)? {
        send_to_raw(buf, view.daddr())?;
    }
    build_segment(view, start, end, buf)?;
    send_to_raw(buf, view.daddr())?;

    Ok(())
}

/// Upper bound of TCP payload bytes carried by a single injected
/// packet.
///
/// Packets handed to us may be larger than the path MTU (GSO skbs on
/// linux, LSO on windows), and writing such a packet to a raw socket
/// fails with EMSGSIZE. Keep every injected packet below the IPv6
/// minimum MTU: 1280 - 40 (IPv6 header) - 60 (max TCP header) = 1180,
/// rounded down for headroom.
const MAX_SEGMENT_PAYLOAD: u32 = 1160;

fn send_split(view: &PktView, order: &[opt::Segment], buf: &mut Vec<u8>) -> Result<()> {
    let payload_len = view.tcp.payload().len() as u32;

    for &opt::Segment(start, end) in order {
        if start >= payload_len {
            crate::warn!(
                "send_split: segment {} exceeds payload len {payload_len}, skipping",
                opt::Segment(start, end)
            );
            continue;
        }

        // `end == u32::MAX` means "until the end of payload".
        let is_bounded = end != u32::MAX && end <= payload_len;
        let seg_end = end.min(payload_len);

        let mut chunk_start = start;
        while chunk_start < seg_end {
            let chunk_end = chunk_start.saturating_add(MAX_SEGMENT_PAYLOAD).min(seg_end);
            let chunk_end_opt = if chunk_end == payload_len {
                None
            } else {
                Some(chunk_end)
            };
            send_segment(view, chunk_start, chunk_end_opt, buf)?;
            chunk_start = chunk_end;
        }

        if is_bounded && opt::delay_ms() > 0 {
            std::thread::sleep(std::time::Duration::from_millis(opt::delay_ms()));
        }
    }

    crate::debug!(
        "send_split: dst={} order={:?} tcp_payload_len={}",
        view.daddr(),
        order,
        payload_len
    );

    Ok(())
}

/// Hop counts above this are treated as an inference failure.
///
/// Real internet paths are rarely longer than ~30 hops. A larger
/// result almost always means the server uses a non-standard initial
/// TTL (e.g. facebook.com, see
/// https://github.com/dilluti0n/dpibreak/issues/20), and trusting it
/// would let the fake ClientHello reach the server.
const MAX_PLAUSIBLE_HOPS: u8 = 32;

/// Crudely infer hop from ttl
///
/// Assume server initial TTL is one of: 64, 128, 255.
/// Pick the smallest origin that can produce the observed TTL (origin >= ttl),
/// then hops = origin - ttl.
///
/// Returns `None` if the result is implausible (> [`MAX_PLAUSIBLE_HOPS`]),
/// in which case the caller should fall back to a fixed TTL.
fn infer_hops(ttl: u8) -> Option<u8> {
    let origin = if ttl <= 64 {
        64u8
    } else if ttl <= 128 {
        128u8
    } else {
        255u8
    };

    let hops = origin - ttl;
    (hops <= MAX_PLAUSIBLE_HOPS).then_some(hops)
}

fn put_hop_1(pkt: &[u8]) -> Result<()> {
    let view = PktView::from_raw(pkt)?;
    let addr = view.saddr();
    let ttl = view.ttl();

    let Some(hop) = infer_hops(ttl) else {
        crate::debug!(
            "put_hop_1: {}: observed ttl={} gives implausible hop count; not cached",
            addr,
            ttl
        );
        return Ok(());
    };

    crate::debug!("put_hop_1: {}: observed ttl={}, put hop={}", addr, ttl, hop);

    hoptab::put(addr, hop);

    Ok(())
}

/// Read pkt and put ip,hop to [`HopTab`]
pub fn put_hop(pkt: &[u8]) {
    if let Err(e) = put_hop_1(pkt) {
        crate::warn!("put_hop: {}", e);
    }
}

/// Return Ok(true) if packet is handled
pub fn handle_packet(pkt: &[u8], buf: &mut Vec<u8>) -> Result<bool> {
    #[cfg(target_os = "linux")]
    let is_filtered = platform::is_kernel_filtered_clienthello();

    #[cfg(windows)]
    let is_filtered = true;

    let view = PktView::from_raw(pkt)?;

    if !is_filtered && !tls::is_client_hello(view.tcp.payload()) {
        return Ok(false);
    }

    // TODO: if clienthello packet has been (unlikely) fragmented,
    // we should find the second part and drop, reassemble it here.

    send_split(&view, opt::segment_order().segments(), buf)?;

    Ok(true)
}

#[macro_export]
macro_rules! handle_packet {
    ($bytes:expr, $buf:expr, handled => $on_handled:expr, rejected => $on_rejected:expr $(,)?) => {{
        match $crate::pkt::handle_packet($bytes, $buf) {
            Ok(true) => $on_handled,
            Ok(false) => $on_rejected,
            Err(e) => {
                $crate::warn!("handle_packet: {e}");
                $on_rejected
            }
        }
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn infer_hops_standard_origins() {
        assert_eq!(infer_hops(64), Some(0));
        assert_eq!(infer_hops(52), Some(12));
        assert_eq!(infer_hops(115), Some(13));
        assert_eq!(infer_hops(128), Some(0));
        assert_eq!(infer_hops(240), Some(15));
        assert_eq!(infer_hops(255), Some(0));
    }

    #[test]
    fn infer_hops_rejects_implausible() {
        // facebook.com case from issue #20: ttl 86 -> 42 "hops" from 128
        assert_eq!(infer_hops(86), None);
        assert_eq!(infer_hops(1), None);
        assert_eq!(infer_hops(129), None);
        assert_eq!(
            infer_hops(64 - MAX_PLAUSIBLE_HOPS),
            Some(MAX_PLAUSIBLE_HOPS)
        );
        assert_eq!(infer_hops(64 - MAX_PLAUSIBLE_HOPS - 1), None);
    }
}
