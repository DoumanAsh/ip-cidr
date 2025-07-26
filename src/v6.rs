//!IPv6 module

use core::net;

use crate::base;

pub(crate) const BITS_LEN: u8 = net::Ipv6Addr::BITS as u8;

///IPv6 CIDR
pub type Cidr = base::Cidr<net::Ipv6Addr>;

impl base::NetworkAddress for net::Ipv6Addr {
    const BITS_LEN: u8 = BITS_LEN;
}

crate::base::impl_base_methods!(net::Ipv6Addr where REPR=u128);
