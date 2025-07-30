use core::net;

use ip_cidr::Cidr;
use ip_cidr::ParseError;

#[cfg_attr(miri, ignore)]
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

#[test]
fn should_parse_ipv6() {
    let inputs = [
        ("::1:2:3:4:5", net::Ipv6Addr::new(0,0,0,1,2,3,4,5)),
        ("0:0:0:1:2:3:4:5", net::Ipv6Addr::new(0,0,0,1,2,3,4,5)),
        ("1:2::3:4:5", net::Ipv6Addr::new(1,2,0,0,0,3,4,5)),
        ("1:2:0:0:0:3:4:5", net::Ipv6Addr::new(1,2,0,0,0,3,4,5)),
        ("1:2:3:4:5::", net::Ipv6Addr::new(1,2,3,4,5,0,0,0)),
        ("1:2:3:4:5:0:0:0", net::Ipv6Addr::new(1,2,3,4,5,0,0,0)),
        ("0:0:0:0:0:ffff:102:405", net::Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x102, 0x405)),
        ("::", net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)),
        ("::0", net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)),
        ("::1", net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
        ("0:0:0::1", net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
        ("ffff::1", net::Ipv6Addr::new(0xffff, 0, 0, 0, 0, 0, 0, 1)),
        ("ffff:0:0:0:0:0:0:1", net::Ipv6Addr::new(0xffff, 0, 0, 0, 0, 0, 0, 1)),
        ("2001:0db8:0a0b:12f0:0:0:0:1", net::Ipv6Addr::new(0x2001, 0x0db8, 0x0a0b, 0x12f0, 0, 0, 0, 1)),
        ("2001:db8:a0b:12f0::1", net::Ipv6Addr::new(0x2001, 0x0db8, 0x0a0b, 0x12f0, 0, 0, 0, 1)),
        ("::ffff:1:2:3:4", net::Ipv6Addr::new(0, 0, 0, 0xffff, 1, 2, 3, 4)),
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
fn should_not_parse_ipv6() {
    let inputs = [
        ("", ParseError::MissingIp),
        ("-f:", ParseError::UnexpectedCharacter('-', 0)),
        ("%f::", ParseError::UnexpectedCharacter('%', 0)),
        ("0:0:0", ParseError::Ipv6InvalidComponentSize(3)),
        ("1:2:3:4:5:6:7:8:9", ParseError::Ipv6InvalidComponentSize(9)),
        ("0:::", ParseError::Ipv6MultipleZeroAbbrv),
        ("1ffff::", ParseError::InvalidComponent("1ffff")),
        ("f", ParseError::InvalidIp),
        ("f:f", ParseError::Ipv6InvalidComponentSize(2)),
        ("1:f", ParseError::Ipv6InvalidComponentSize(2)),
        ("f:1", ParseError::Ipv6InvalidComponentSize(2)),
        ("ffff::/129", ParseError::Ipv6CidrPrefixOverflow(129)),
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
