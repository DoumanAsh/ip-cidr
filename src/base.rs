//! Base module

use core::fmt;

///Network address trait
pub trait NetworkAddress: Clone + Copy + fmt::Debug + fmt::Display + PartialEq + Eq + PartialOrd + Ord {
    ///Max possible length of the address in bits
    const BITS_LEN: u8;
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
///CIDR representation of IPv4 network
pub struct Cidr<A> {
    prefix: u8,
    addr: A,
}

impl<A: NetworkAddress> Cidr<A> {
    #[inline]
    ///Constructs new CIDR verifying that `prefix` fits provided `addrs`
    ///
    ///Returns `None` if `prefix` is greater than address length
    pub const fn new(addr: A, prefix: u8) -> Option<Self> {
        if prefix > A::BITS_LEN {
            None
        } else {
            Some(Self {
                addr,
                prefix,
            })
        }
    }

    #[inline(always)]
    ///Returns address
    pub const fn addr(&self) -> A {
        self.addr
    }

    #[inline(always)]
    ///Returns prefix
    pub const fn prefix(&self) -> u8 {
        self.prefix
    }
}

impl<A: NetworkAddress> fmt::Display for Cidr<A> {
    #[inline(always)]
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { addr, prefix } = self;
        fmt.write_fmt(format_args!("{addr}/{prefix}"))
    }
}

macro_rules! impl_base_methods {
    ($typ:ty where REPR=$repr:ident) => {
        #[inline]
        ///Computes network mask for provided `prefix`, assuming `prefix` is valid prefix
        pub const fn mask(prefix: u8) -> $typ {
            match prefix {
                0 => <$typ>::UNSPECIFIED,
                prefix => {
                    let mask = $repr::MAX << (BITS_LEN.saturating_sub(prefix));
                    <$typ>::from_bits(mask)
                }
            }
        }

        #[inline]
        ///Computes network address from provided `addr` and `prefix`, which is lowest possible address within CIDR block
        pub const fn network_addr(addr: $typ, prefix: u8) -> $typ {
            let mask = mask(prefix).to_bits();
            let addr = addr.to_bits() & mask;
            <$typ>::from_bits(addr)
        }

        #[inline]
        ///Computes network address from provided `addr` and `prefix`, which is highest possible address within CIDR block
        pub const fn broadcast_addr(addr: $typ, prefix: u8) -> $typ {
            let mask = mask(prefix).to_bits();
            let broadcast = addr.to_bits() | !mask;
            <$typ>::from_bits(broadcast)
        }

        #[inline]
        ///Returns number of possible addresses
        pub const fn size(prefix: u8) -> $repr {
            match prefix {
                0 => $repr::MAX,
                prefix => 1 << (BITS_LEN.saturating_sub(prefix))
            }
        }

        impl $crate::base::Cidr<$typ> {
            #[inline(always)]
            ///Computes network address from provided `addr` and `prefix`, which is lowest possible address within CIDR block
            pub const fn network_addr(&self) -> $typ {
                network_addr(self.addr(), self.prefix())
            }

            #[inline(always)]
            ///Computes network address from provided `addr` and `prefix`, which is highest possible address within CIDR block
            pub const fn broadcast_addr(&self) -> $typ {
                broadcast_addr(self.addr(), self.prefix())
            }

            #[inline(always)]
            ///Checks if a given `addr` is contained within `self`
            pub const fn contains(&self, addr: $typ) -> bool {
                (addr.to_bits() & mask(self.prefix()).to_bits()) == self.network_addr().to_bits()
            }

            #[inline(always)]
            ///Returns number of possible addresses
            pub const fn size(&self) -> $repr {
                size(self.prefix())
            }

            #[inline(always)]
            ///Attempts to fetch address by `idx` within the block `self`
            pub const fn get(&self, idx: $repr) -> Option<$typ> {
                if idx >= self.size() {
                    return None;
                }

                Some(self.get_unchecked(idx))
            }

            #[inline]
            ///Returns address corresponding `idx` without checking size according to the prefix
            ///
            ///This is safe in a sense as it is only wrapping math operation, but it should be only used
            ///when you know need to iterate over possible addresses by pre-computing size
            pub const fn get_unchecked(&self, idx: $repr) -> $typ {
                let net = self.network_addr().to_bits();
                <$typ>::from_bits(net.wrapping_add(idx))
            }
        }
    }
}

pub(super) use impl_base_methods;
