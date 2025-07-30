use core::{fmt, net, slice, ptr};

enum FamilyType {
    Unknown,
    V4,
    V6,
}

#[derive(Debug)]
enum ParserState {
    Initial,
    Digit,
    V4Sep,
    V6Sep,
}

mod flag {
    pub const IS_IPV6_ZERO_SKIP: u8 = 0b010;
    pub const IS_IPV6_SEP_INITIAL: u8 = 0b100;
}

struct Parser<'a> {
    state: ParserState,
    family: FamilyType,
    flags: u8,
    //Number of address components
    //For IPv4 it is always 4
    //For normal IPv6 it is always 8
    components_size: u8,
    components: [u16; 8],
    zero_component_start: u8,
    start_digit_position: usize,
    text: &'a [u8],
}

impl<'a> Parser<'a> {
    const fn extract_component(&mut self, component_sep_pos: usize) -> Option<ParseError<'a>> {
        let text = unsafe {
            core::str::from_utf8_unchecked(
                slice::from_raw_parts(self.text.as_ptr().add(self.start_digit_position), component_sep_pos.saturating_sub(self.start_digit_position))
            )
        };

        let result = match self.family {
            FamilyType::V4 => {
                if self.components_size >= 4 {
                    return Some(ParseError::Ipv4InvalidComponentSize(self.components_size.saturating_add(1)));
                }

                u16::from_str_radix(text, 10)
            },
            FamilyType::V6 => {
                if self.components_size >= 8 {
                    return Some(ParseError::Ipv6InvalidComponentSize(self.components_size.saturating_add(1)));
                }

                u16::from_str_radix(text, 16)
            },
            FamilyType::Unknown => return None,
        };

        match result {
            Ok(component) => {
                self.components[self.components_size as usize] = component;
                self.components_size = self.components_size.saturating_add(1);
                self.start_digit_position = 0;
                None
            },
            Err(_) => Some(ParseError::InvalidComponent(text)),
        }
    }

    const fn read_ip(&mut self) -> Result<net::IpAddr, ParseError<'a>> {
        const IPV4_LEN: u8 = 4;
        const IPV6_LEN: u8 = 8;

        macro_rules! read_octet {
            ($idx:expr) => {
                match self.components[$idx] {
                    octet @ 0..=255 => octet as u8,
                    octet => return Err(ParseError::Ipv4ComponentOverflow(octet))
                }
            };
        }

        match self.family {
            FamilyType::V4 => if self.components_size == IPV4_LEN {
                let a = read_octet!(0);
                let b = read_octet!(1);
                let c = read_octet!(2);
                let f = read_octet!(3);
                Ok(net::IpAddr::V4(net::Ipv4Addr::new(a, b, c, f)))
            } else {
                return Err(ParseError::Ipv4InvalidComponentSize(self.components_size));
            },
            FamilyType::V6 => if self.components_size > IPV6_LEN {
                Err(ParseError::InvalidIpv6)
            } else {
                if self.components_size < IPV6_LEN {
                    if self.flags & flag::IS_IPV6_ZERO_SKIP == flag::IS_IPV6_ZERO_SKIP {
                        let zero_len = IPV6_LEN.saturating_sub(self.components_size);

                        unsafe {
                            //always use the *same* pointer otherwise miri will complain about retag
                            let components_ptr = self.components.as_mut_ptr();
                            ptr::copy(
                                components_ptr.add(self.zero_component_start as _),
                                components_ptr.add(self.zero_component_start.saturating_add(zero_len) as _),
                                self.components_size.saturating_sub(self.zero_component_start) as _);
                            ptr::write_bytes(components_ptr.add(self.zero_component_start as _), 0, zero_len as _);
                        }

                    } else {
                        return Err(ParseError::Ipv6InvalidComponentSize(self.components_size));
                    }
                }

                let ip = net::Ipv6Addr::new(
                    self.components[0], self.components[1],
                    self.components[2], self.components[3],
                    self.components[4], self.components[5],
                    self.components[6], self.components[7]
                );
                Ok(net::IpAddr::V6(ip))
            },
            FamilyType::Unknown => match self.state {
                ParserState::Initial => Err(ParseError::MissingIp),
                _ => Err(ParseError::InvalidIp),
            }
        }
    }

    #[inline(always)]
    const fn on_digit(&mut self, pos: usize) -> Option<ParseError<'a>> {
        match self.state {
            ParserState::Digit => None,
            ParserState::V6Sep if self.flags & flag::IS_IPV6_SEP_INITIAL == flag::IS_IPV6_SEP_INITIAL => Some(ParseError::InvalidIpv6),
            _ => {
                self.state = ParserState::Digit;
                self.start_digit_position = pos;
                None
            }
        }
    }

    #[inline(always)]
    const fn on_v4_sep(&mut self, pos: usize) -> Option<ParseError<'a>> {
        let result = match self.state {
            ParserState::Digit => match self.family {
                FamilyType::V6 => return Some(ParseError::InvalidIpv6),
                FamilyType::Unknown => {
                    self.family = FamilyType::V4;
                    self.extract_component(pos)
                },
                FamilyType::V4 => self.extract_component(pos),
            },
            ParserState::V4Sep | ParserState::V6Sep | ParserState::Initial => Some(ParseError::InvalidIpv4),
        };
        self.state = ParserState::V4Sep;
        result
    }

    #[inline(always)]
    const fn on_v6_sep(&mut self, pos: usize) -> Option<ParseError<'a>> {
        let result = match self.state {
            ParserState::Digit => match self.family {
                FamilyType::V4 => return Some(ParseError::InvalidIpv4),
                FamilyType::Unknown => {
                    self.family = FamilyType::V6;
                    self.extract_component(pos)
                },
                FamilyType::V6 => self.extract_component(pos),
            },
            ParserState::V6Sep => {
                //Only 1 zero skip is allowed
                if (self.flags & flag::IS_IPV6_ZERO_SKIP) == flag::IS_IPV6_ZERO_SKIP {
                    return Some(ParseError::Ipv6MultipleZeroAbbrv);
                } else {
                    self.flags = (self.flags & !flag::IS_IPV6_SEP_INITIAL) | flag::IS_IPV6_ZERO_SKIP;
                    self.zero_component_start = self.components_size;
                    self.family = FamilyType::V6;
                    return None
                }
            },
            //You can start with double ::
            ParserState::Initial => {
                self.flags |= flag::IS_IPV6_SEP_INITIAL;
                None
            }
            ParserState::V4Sep => Some(ParseError::InvalidIpv4),
        };

        self.state = ParserState::V6Sep;
        result
    }

    //Handles last address component if any
    const fn on_ip_end(&mut self, pos: usize) -> Result<net::IpAddr, ParseError<'a>> {
        match self.state {
            ParserState::Digit => {
                match self.extract_component(pos) {
                    None => self.read_ip(),
                    Some(error) => Err(error),
                }
            }
            ParserState::V4Sep => Err(ParseError::InvalidIpv4),
            ParserState::V6Sep if self.flags & flag::IS_IPV6_ZERO_SKIP == flag::IS_IPV6_ZERO_SKIP => {
                if self.components_size == 0 {
                    Ok(net::IpAddr::V6(net::Ipv6Addr::UNSPECIFIED))
                } else {
                    self.read_ip()
                }
            },
            ParserState::V6Sep => Err(ParseError::InvalidIpv6),
            ParserState::Initial => Err(ParseError::MissingIp),
        }
    }

    //Extracts prefix after `pos`
    const fn on_cidr_sep(&mut self, pos: usize) -> Result<u8, ParseError<'a>> {
        let digit_pos = pos.saturating_add(1);
        if digit_pos >= self.text.len() {
            return Err(ParseError::MissingCidr);
        }

        let text = unsafe {
            core::str::from_utf8_unchecked(
                slice::from_raw_parts(self.text.as_ptr().add(digit_pos), self.text.len().saturating_sub(digit_pos))
            )
        };

        match u8::from_str_radix(text, 10) {
            Ok(result) => match self.family {
                FamilyType::V4 => {
                    if result > crate::v4::BITS_LEN {
                        Err(ParseError::Ipv4CidrPrefixOverflow(result))
                    } else {
                        Ok(result)
                    }
                },
                FamilyType::V6 => {
                    if result > crate::v6::BITS_LEN {
                        Err(ParseError::Ipv6CidrPrefixOverflow(result))
                    } else {
                        Ok(result)
                    }
                },
                FamilyType::Unknown => Err(ParseError::InvalidCidr(text))
            }
            Err(_) => Err(ParseError::InvalidCidr(text)),
        }
    }

    const fn parse(&mut self) -> Result<(net::IpAddr, Option<u8>), ParseError<'a>> {
        let mut idx = 0;

        while idx < self.text.len() {
            let ch = self.text[idx];
            if ch.is_ascii_hexdigit() {
                if let Some(error) = self.on_digit(idx) {
                    return Err(error);
                }
            } else if ch == b'.' {
                if let Some(error) = self.on_v4_sep(idx) {
                    return Err(error)
                }
            } else if ch == b':' {
                if let Some(error) = self.on_v6_sep(idx) {
                    return Err(error)
                }
            } else if ch == b'/' {
                let ip = match self.on_ip_end(idx) {
                    Ok(extracted_ip) => extracted_ip,
                    Err(error) => return Err(error),
                };
                match self.on_cidr_sep(idx) {
                    Ok(cidr) => return Ok((ip, Some(cidr))),
                    Err(error) => return Err(error),
                }
            } else if ch.is_ascii() {
                return Err(ParseError::UnexpectedCharacter(ch as _, idx));
            } else {
                return Err(ParseError::UnexpectedCharacter(ch as _, idx));
            }

            idx = idx + 1;
        }

        match self.on_ip_end(idx) {
            Ok(ip) => Ok((ip, None)),
            Err(error) => Err(error)
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
///Possible errors parsings IP addr
pub enum ParseError<'a> {
    ///Invalid address component
    InvalidComponent(&'a str),
    ///Invalid CIDR prefix
    InvalidCidr(&'a str),
    ///Unexpected character with position where it is encountered at
    UnexpectedCharacter(char, usize),
    ///Input is not valid IP
    InvalidIp,
    ///Address is not valid IPv4
    InvalidIpv4,
    ///IPv4 Address must have 4 components
    Ipv4InvalidComponentSize(u8),
    ///IPv4 Address component is greater than 255
    Ipv4ComponentOverflow(u16),
    ///Address is not valid IPv6
    InvalidIpv6,
    ///IPv6 Address must have 4 components
    Ipv6InvalidComponentSize(u8),
    ///IPv6 contains more than 1 zero abbreviation
    Ipv6MultipleZeroAbbrv,
    ///Unexpected Non-ASCII character encountered
    NonAsciiCharacter(usize),
    ///IP address is not specified
    MissingIp,
    ///Prefix is not specified
    MissingCidr,
    ///Prefix is greater than 32
    Ipv4CidrPrefixOverflow(u8),
    ///Prefix is greater than 128
    Ipv6CidrPrefixOverflow(u8),
}

impl fmt::Display for ParseError<'_> {
    #[inline]
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIp => fmt.write_str("Input is not valid IP"),
            Self::InvalidIpv4 => fmt.write_str("Address is not valid IPv4"),
            Self::InvalidIpv6 => fmt.write_str("Address is not valid IPv6"),
            Self::Ipv4InvalidComponentSize(size) => fmt.write_fmt(format_args!("IPv4 Address has '{size}' components but expected 4")),
            Self::Ipv6InvalidComponentSize(size) => fmt.write_fmt(format_args!("IPv6 Address has '{size}' components but expected 8")),
            Self::Ipv6MultipleZeroAbbrv => fmt.write_str("IPv6 contains more than 1 zero abbreviation"),
            Self::Ipv4ComponentOverflow(size) => fmt.write_fmt(format_args!("IPv4 component is '{size}' while allowed range is 0..=255")),
            Self::UnexpectedCharacter(ch, pos) => fmt.write_fmt(format_args!("Encountered unexpected character '{ch}' at idx={pos}")),
            Self::InvalidCidr(cidr) => {
                fmt.write_str("Invalid Cidr prefix: ")?;
                fmt.write_str(cidr)
            },
            Self::InvalidComponent(addr) => {
                fmt.write_str("Invalid address component: ")?;
                fmt.write_str(addr)
            },
            Self::NonAsciiCharacter(pos) => fmt.write_fmt(format_args!("Encountered non-ASCII character at idx={pos}")),
            Self::MissingIp => fmt.write_str("Address is not specified"),
            Self::MissingCidr => fmt.write_str("Prefix is not specified"),
            Self::Ipv4CidrPrefixOverflow(prefix) => fmt.write_fmt(format_args!("Prefix '{prefix}' is greater than 32")),
            Self::Ipv6CidrPrefixOverflow(prefix) => fmt.write_fmt(format_args!("Prefix '{prefix}' is greater than 128")),
        }
    }
}

///Performs parsing of the string into IP addr with optional CIDR prefix
pub const fn parse_ip(text: &str) -> Result<(net::IpAddr, Option<u8>), ParseError<'_>> {
    let text = text.as_bytes();

    let mut parser = Parser {
        state: ParserState::Initial,
        flags: 0,
        family: FamilyType::Unknown,
        components_size: 0,
        components: [0; 8],
        zero_component_start: 0,
        start_digit_position: 0,
        text,
    };
    parser.parse()
}
