//!IPv4 module

use core::net;

use crate::base;

pub(crate) const BITS_LEN: u8 = net::Ipv4Addr::BITS as u8;

///IPv4 CIDR
pub type Cidr = base::Cidr<net::Ipv4Addr>;

impl base::NetworkAddress for net::Ipv4Addr {
    const BITS_LEN: u8 = BITS_LEN;
}

crate::base::impl_base_methods!(net::Ipv4Addr where REPR=u32);
