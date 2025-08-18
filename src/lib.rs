//! IP matching utilities

#![no_std]
#![warn(missing_docs)]
#![allow(clippy::style)]

mod parser;
pub use parser::{parse_ip, ParseError};
pub mod base;
pub mod v4;
pub mod v6;

use core::{fmt, net};

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
///CIDR representation
pub enum Cidr {
    ///IPv4 block
    V4(v4::Cidr),
    ///IPv6 block
    V6(v6::Cidr),
}

impl Cidr {
    ///Number of bits within ipv4 address
    pub const IPV4_BITS: u8 = v4::BITS_LEN;
    ///Number of bits within ipv6 address
    pub const IPV6_BITS: u8 = v6::BITS_LEN;

    #[inline(always)]
    ///Constructs new CIDR verifying that `prefix` fits provided `addrs`
    ///
    ///Returns `None` if `prefix` is greater than address length
    pub const fn new(addr: net::IpAddr, prefix: u8) -> Option<Self> {
        match addr {
            net::IpAddr::V4(addr) => Self::new_v4(addr, prefix),
            net::IpAddr::V6(addr) => Self::new_v6(addr, prefix),
        }
    }

    #[inline]
    ///Constructs new CIDR verifying that `prefix` fits provided `addrs`
    ///
    ///Returns `None` if `prefix` is greater than address length
    pub const fn new_v4(addr: net::Ipv4Addr, prefix: u8) -> Option<Self> {
        match v4::Cidr::new(addr, prefix) {
            Some(cidr) => Some(Self::V4(cidr)),
            None => None,
        }
    }

    #[inline]
    ///Constructs new CIDR verifying that `prefix` fits provided `addrs`
    ///
    ///Returns `None` if `prefix` is greater than address length
    pub const fn new_v6(addr: net::Ipv6Addr, prefix: u8) -> Option<Self> {
        match v6::Cidr::new(addr, prefix) {
            Some(cidr) => Some(Self::V6(cidr)),
            None => None,
        }
    }

    #[inline(always)]
    ///Returns address
    pub const fn addr(&self) -> net::IpAddr {
        match self {
            Self::V4(cidr) => net::IpAddr::V4(cidr.addr()),
            Self::V6(cidr) => net::IpAddr::V6(cidr.addr()),
        }
    }

    #[inline(always)]
    ///Returns prefix
    pub const fn prefix(&self) -> u8 {
        match self {
            Self::V4(cidr) => cidr.prefix(),
            Self::V6(cidr) => cidr.prefix(),
        }
    }

    #[inline(always)]
    ///Computes network address from provided `addr` and `prefix`, which is lowest possible address within CIDR block
    pub const fn network_addr(&self) -> net::IpAddr {
        match self {
            Self::V4(cidr) => net::IpAddr::V4(cidr.network_addr()),
            Self::V6(cidr) => net::IpAddr::V6(cidr.network_addr()),
        }
    }

    #[inline(always)]
    ///Computes network address from provided `addr` and `prefix`, which is highest possible address within CIDR block
    pub const fn broadcast_addr(&self) -> net::IpAddr {
        match self {
            Self::V4(cidr) => net::IpAddr::V4(cidr.broadcast_addr()),
            Self::V6(cidr) => net::IpAddr::V6(cidr.broadcast_addr()),
        }
    }

    #[inline(always)]
    ///Returns maximum number of addresses within the block
    pub const fn size(&self) -> u128 {
        match self {
            Self::V4(cidr) => cidr.size() as _,
            Self::V6(cidr) => cidr.size(),
        }
    }

    #[inline(always)]
    ///Checks if a given `addr` is contained within `self`
    pub const fn contains(&self, addr: net::IpAddr) -> bool {
        match (self, addr) {
            (Self::V4(cidr), net::IpAddr::V4(addr)) => cidr.contains(addr),
            (Self::V6(cidr), net::IpAddr::V6(addr)) => cidr.contains(addr),
            _ => false,
        }
    }

    #[inline(always)]
    ///Attempts to fetch address by `idx` within the block `self`
    pub const fn get(&self, idx: u128) -> Option<net::IpAddr> {
        match self {
            Self::V4(cidr) => match cidr.get(idx as u32) {
                Some(ip) => Some(net::IpAddr::V4(ip)),
                None => None,
            }
            Self::V6(cidr) => match cidr.get(idx) {
                Some(ip) => Some(net::IpAddr::V6(ip)),
                None => None,
            }
        }
    }

    #[inline(always)]
    ///Returns address corresponding `idx` without checking size according to the prefix
    ///
    ///This is safe in a sense as it is only wrapping math operation, but it should be only used
    ///when you know need to iterate over possible addresses by pre-computing size
    pub const fn get_unchecked(&self, idx: u128) -> net::IpAddr {
        match self {
            Self::V4(cidr) => net::IpAddr::V4(cidr.get_unchecked(idx as u32)),
            Self::V6(cidr) => net::IpAddr::V6(cidr.get_unchecked(idx)),
        }
    }
}

impl fmt::Display for Cidr {
    #[inline(always)]
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4(cidr) => fmt::Display::fmt(cidr, fmt),
            Self::V6(cidr) => fmt::Display::fmt(cidr, fmt),
        }
    }
}

#[inline]
///Parses [Cidr](enum.Cidr.html) from the input `text`
///
///Returning `Err` if string contains invalid IP or CIDR's prefix
///
///Returns `Ok(None)` if `text` is valid CIDR but `prefix` overflows
///
///If `prefix` is missing, prefix is assumed to be only for single IP:
///- In case of IPv4 it means prefix is assumed to be 32
///- In case of IPv6 it means prefix is assumed to be 128
pub const fn parse_cidr(text: &str) -> Result<Option<Cidr>, parser::ParseError<'_>> {
    match parse_ip(text) {
        Ok((net::IpAddr::V4(addr), None)) => Ok(Some(Cidr::V4(v4::Cidr::new_single(addr)))),
        Ok((net::IpAddr::V4(addr), Some(prefix))) => Ok(Cidr::new_v4(addr, prefix)),
        Ok((net::IpAddr::V6(addr), None)) => Ok(Some(Cidr::V6(v6::Cidr::new_single(addr)))),
        Ok((net::IpAddr::V6(addr), Some(prefix))) => Ok(Cidr::new_v6(addr, prefix)),
        Err(error) => Err(error)
    }
}
