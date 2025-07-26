use core::net;

use ip_cidr::Cidr;

#[test]
fn should_verify_v6_prefix_size() {
    let addr = net::Ipv6Addr::UNSPECIFIED;

    let mut cidr = Cidr::new_v6(addr, 0).expect("to create");
    //Broadcast address is never included
    assert_eq!(cidr.size(), u128::MAX as _, "/0 has invalid size");
    assert_eq!(cidr.get(u128::MAX as _), None);
    assert_eq!(cidr.get((u128::MAX - 1) as _), Some(net::Ipv6Addr::new(u16::MAX, u16::MAX, u16::MAX, u16::MAX, u16::MAX, u16::MAX, u16::MAX, u16::MAX - 1).into()));
    for prefix in 1..=64 {
        cidr = Cidr::new_v6(addr, prefix).expect("to create");
        let expected_size = 2u128.pow((128 - prefix) as _);
        assert_eq!(cidr.size(), expected_size, "/{} has invalid size", prefix);

        let mut addr = net::IpAddr::V6(net::Ipv6Addr::from_bits(0));
        assert!(cidr.contains(addr), "{} is not contained in cidr={}", addr, cidr);
        addr = net::IpAddr::V6(net::Ipv6Addr::from_bits(expected_size - 1));
        assert!(cidr.contains(addr), "{} is not contained in cidr={}", addr, cidr);
    }

    //check math never panics
    cidr = Cidr::new_v6(net::Ipv6Addr::new(u16::MAX, u16::MAX, u16::MAX, u16::MAX, u16::MAX, u16::MAX, u16::MAX, u16::MAX - 3), 127).expect("to create");
    assert_eq!(cidr.size(), 2);
    assert_eq!(cidr.get_unchecked(0), net::IpAddr::V6(net::Ipv6Addr::new(u16::MAX, u16::MAX, u16::MAX, u16::MAX, u16::MAX, u16::MAX, u16::MAX, u16::MAX - 3)));
    assert_eq!(cidr.get_unchecked(1), net::IpAddr::V6(net::Ipv6Addr::new(u16::MAX, u16::MAX, u16::MAX, u16::MAX, u16::MAX, u16::MAX, u16::MAX, u16::MAX - 2)));
    assert_eq!(cidr.get_unchecked(2), net::IpAddr::V6(net::Ipv6Addr::new(u16::MAX, u16::MAX, u16::MAX, u16::MAX, u16::MAX, u16::MAX, u16::MAX, u16::MAX - 1)));

    //wrap
    assert_eq!(cidr.get_unchecked(3), net::IpAddr::V6(net::Ipv6Addr::new(u16::MAX, u16::MAX, u16::MAX, u16::MAX, u16::MAX, u16::MAX, u16::MAX, u16::MAX)));
    assert_eq!(cidr.get_unchecked(4), net::IpAddr::V6(net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)));

}
