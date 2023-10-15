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
fn it_works() {
    use scarust::*;
    let ip = Ip {
        ..Default::default()
    };
    eprintln!("{:?}", ip);
    assert_eq!(2 + 2, 4);
}

#[test]
fn custom_proto() {
    use scarust::*;
    let px = TestProto!().tos(2);
    println!("created: {:?}", &px);
    assert_eq!(px.version, Value::Set(4));
    assert_eq!(px.tos, Value::Set(2));
    assert_eq!(px.mac2, Value::Random);
    assert_eq!(px.mac3, "00:01:02:03:04:05".into());
    let fx = px.clone().to_stack().fill();
    println!("filled: {:?}", &fx);
    assert_ne!(fx[TestProto!()].mac2, Value::Random);
    let bytes = fx.encode();
    println!("bytes: {:?}", &bytes);
    assert_eq!(bytes[0], 2); // tos
}
