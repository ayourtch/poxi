use scarust::Value::Random;
use scarust::*;
#[macro_use]
extern crate scarust_derive;
use scarust::protocols::all::*;

#[derive(FromStringHashmap, NetworkProtocol, Clone, Debug, Eq, PartialEq)]
pub struct testProto {
    #[nproto(default = 4, encode = Skip)]
    pub version: Value<u8>,
    pub tos: Value<u8>,
    pub mac1: Value<MacAddr>,
    #[nproto(default = Random)]
    pub mac2: Value<MacAddr>,
    #[nproto(default = "00:01:02:03:04:05")]
    pub mac3: Value<MacAddr>,
    #[nproto(default = Random)]
    pub id: Value<u16>,
}

#[test]
fn encode_arp() {
    let x = Ether!(src = "02:02:02:02:02:02")
        / ARP!(
            psrc = "1.1.1.1",
            pdst = "2.2.2.2",
            hwdst = "ff:ff:ff:ff:ff:ff"
        );
    eprintln!("Initial: {:02x?}", &x);
    let filled = x.fill();
    assert_eq!(filled[Ether!()].etype, Value::Set(0x0806));
    let encoded = filled.clone().encode();
    eprintln!("Filled: {:02x?}", &filled);
    eprintln!("Encoded: {:02x?}", &encoded);
}

#[test]
fn make_random_encode() {
    let x = Ether!(src = "02:02:02:02:02:02")
        / IP!(src = "10.10.10.10", dst = "11.11.11.11", id = 42, tos = 33)
        / UDP!();
    eprintln!("Initial: {:02x?}", &x);
    let filled = x.fill();
    assert_eq!(filled[IP!()].proto, Value::Set(17));
    let encoded = filled.clone().encode();
    eprintln!("Filled: {:02x?}", &filled);
    eprintln!("Encoded: {:02x?}", &encoded);
    assert_eq!(encoded[12], 0x08);
    assert_eq!(encoded[13], 0x00);
}

#[test]
fn make_tcp_checksum_tiny() {
    let x = IP!(id = 1) / TCP!(sport = 20, dport = 80);
    eprintln!("Initial: {:02x?}", &x);
    let filled = x.fill();
    let encoded = filled.clone().encode();
    eprintln!("Filled: {:02x?}", &filled);
    eprintln!("Encoded: {:02x?}", &encoded);
    // IP checksum
    assert_eq!(encoded[10], 0x7c);
    assert_eq!(encoded[11], 0xcd);
    // TCP checksum
    assert_eq!(encoded[36], 0x91);
    assert_eq!(encoded[37], 0x7c);
}

#[test]
fn make_udp_checksum_tiny() {
    let x = IP!(id = 1) / UDP!(sport = 53, dport = 53);
    eprintln!("Initial: {:02x?}", &x);
    let filled = x.fill();
    let encoded = filled.clone().encode();
    eprintln!("Filled: {:02x?}", &filled);
    eprintln!("Encoded: {:02x?}", &encoded);
    // IP checksum
    assert_eq!(encoded[10], 0x7c);
    assert_eq!(encoded[11], 0xce);
    // UDP checksum
    assert_eq!(encoded[26], 0x01);
    assert_eq!(encoded[27], 0x72);
}

#[test]
fn make_udp_checksum_payload() {
    let x = IP!(id = 1) / UDP!(sport = 1234, dport = 1234) / "xxx".to_string();
    eprintln!("Initial: {:02x?}", &x);
    let filled = x.fill();
    let encoded = filled.clone().encode();
    eprintln!("Filled: {:02x?}", &filled);
    eprintln!("Encoded: {:02x?}", &encoded);
    // IP checksum
    assert_eq!(encoded[10], 0x7c);
    assert_eq!(encoded[11], 0xcb);
    // UDP checksum
    assert_eq!(encoded[26], 0x07);
    assert_eq!(encoded[27], 0xb9);
}
