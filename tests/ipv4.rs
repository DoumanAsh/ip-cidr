use core::net;

use ip_cidr::Cidr;

#[test]
fn should_verify_v4_prefix_size() {
    let addr = net::Ipv4Addr::UNSPECIFIED;

    let mut cidr = Cidr::new_v4(addr, 0).expect("to create");
    //Broadcast address is never included
    assert_eq!(cidr.size(), u32::MAX as _, "/0 has invalid size");
    assert_eq!(cidr.get(u32::MAX as _), None);
    assert_eq!(cidr.get((u32::MAX - 1) as _), Some(net::Ipv4Addr::new(255, 255, 255, 254).into()));

    for prefix in 1..=32 {
        cidr = Cidr::new_v4(addr, prefix).expect("to create");
        let expected_size = 2u128.pow((32 - prefix) as _);
        assert_eq!(cidr.size(), expected_size, "/{} has invalid size", prefix);
        for addr in 0..expected_size as u32 {
            let addr = net::IpAddr::V4(net::Ipv4Addr::from_bits(addr));
            assert!(cidr.contains(addr), "{} is not contained in cidr={}", addr, cidr);
        }
    }

    //check math never panics
    cidr = Cidr::new_v4(net::Ipv4Addr::new(255, 255, 255, 30), 31).expect("to create");
    assert_eq!(cidr.size(), 2);
    assert_eq!(cidr.get_unchecked(0), net::IpAddr::V4(net::Ipv4Addr::new(255, 255, 255, 30)));
    assert_eq!(cidr.get_unchecked(1), net::IpAddr::V4(net::Ipv4Addr::new(255, 255, 255, 31)));
    assert_eq!(cidr.get_unchecked(2), net::IpAddr::V4(net::Ipv4Addr::new(255, 255, 255, 32)));

    //wrap
    assert_eq!(cidr.get_unchecked(225), net::IpAddr::V4(net::Ipv4Addr::new(255, 255, 255, 255)));
    assert_eq!(cidr.get_unchecked(226), net::IpAddr::V4(net::Ipv4Addr::new(0, 0, 0, 0)));
}
