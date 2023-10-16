use scarust::Value::Random;
use scarust::*;
#[macro_use]
extern crate scarust_derive;

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
