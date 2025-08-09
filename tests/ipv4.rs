use core::net;

use ip_cidr::ParseError;
use ip_cidr::Cidr;

#[cfg_attr(miri, ignore)]
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

#[test]
fn should_parse_ipv4() {
    let inputs = [
        ("127.0.0.1", net::Ipv4Addr::new(127, 0, 0, 1)),
        ("0.0.0.0", net::Ipv4Addr::new(0, 0, 0, 0)),
        ("255.255.255.255", net::Ipv4Addr::new(255, 255, 255, 255)),
    ];

    for (prefix, (text, expected_ip)) in inputs.iter().enumerate() {
        println!("Parse '{text}'");
        let (ip, cidr) = match ip_cidr::parse_ip(text) {
            Ok(result) => result,
            Err(error) => panic!("Should parse '{text}' but got error={error}"),
        };
        assert_eq!(ip, *expected_ip);
        assert!(cidr.is_none());

        let with_cidr = format!("{text}/{prefix}");
        println!("Parse '{with_cidr}'");
        let (ip, cidr) = match ip_cidr::parse_ip(&with_cidr) {
            Ok(result) => result,
            Err(error) => panic!("Should parse '{text}' but got error={error}"),
        };
        assert_eq!(ip, *expected_ip);
        assert_eq!(cidr, Some(prefix as u8));
    }

}

#[test]
fn should_not_parse_ipv4() {
    let inputs = [
        ("", ParseError::MissingIp),
        ("-1.", ParseError::UnexpectedCharacter('-', 0)),
        ("%1.", ParseError::UnexpectedCharacter('%', 0)),
        ("0.0.0", ParseError::Ipv4InvalidComponentSize(3)),
        ("127.0.0.1.5", ParseError::Ipv4InvalidComponentSize(5)),
        ("1..", ParseError::InvalidIpv4),
        ("256.0.0.1", ParseError::InvalidComponent("256")),
        ("1", ParseError::InvalidIp),
        ("1.1", ParseError::Ipv4InvalidComponentSize(2)),
        ("1.f", ParseError::InvalidComponent("f")),
        ("f.1", ParseError::InvalidComponent("f")),
        ("127.0.0.1/33", ParseError::Ipv4CidrPrefixOverflow(33)),
        ("127.1.0.900", ParseError::InvalidComponent("900"))
    ];

    for (prefix, (text, expected_error)) in inputs.iter().enumerate() {
        println!("Parse '{text}'");
        let error = ip_cidr::parse_ip(text).expect_err("should fail");
        assert_eq!(error, *expected_error);

        let with_cidr = format!("{text}/{prefix}");
        println!("Parse '{with_cidr}'");
        let error = ip_cidr::parse_ip(text).expect_err("should fail");
        assert_eq!(error, *expected_error);
    }
}
