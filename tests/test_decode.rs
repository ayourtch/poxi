#[test]
fn decode_test_1() {
    use scarust::*;

    let x = Ether!()
        .decode("AAAAAABBBBBB\x08\x00\x4523456789\x111234567890123456789012a".as_bytes())
        .unwrap();
    println!("decode result: {:?}", &x);
    assert_eq!(x.indices_of(Ether!()), vec![0]);
    assert_eq!(x.indices_of(IP!()), vec![1]);
    assert_eq!(x.indices_of(UDP!()), vec![2]);
    let eth = &x[Ether!()];
    assert_eq!(eth.dst, "41:41:41:41:41:41".into());
    assert_eq!(eth.src, "42:42:42:42:42:42".into());
    assert_eq!(eth.etype, Value::Set(0x800));

    eprintln!("{:?}", &x);
}

#[test]
fn decode_test_raw() {
    use scarust::*;

    let x = Ether!()
        .decode("AAAAAABBBBBB\x08\x0112345678901234567890123456789012a".as_bytes())
        .unwrap();
    println!("decode result: {:?}", &x);
    assert_eq!(x.indices_of(Ether!()), vec![0]);
    assert_eq!(x.indices_of(IP!()), vec![]);
    assert_eq!(x.indices_of(Raw!()), vec![1]);
    let eth = &x[Ether!()];
    assert_eq!(eth.dst, "41:41:41:41:41:41".into());
    assert_eq!(eth.src, "42:42:42:42:42:42".into());
    assert_eq!(eth.etype, Value::Set(0x801));

    eprintln!("{:?}", &x);
}

#[test]
fn decode_test_dot1q() {
    use scarust::*;

    let x = Ether!()
        .decode(b"AAAAAABBBBBB\x81\x00\x02\x21\x08\x00\x4523456789\x111234567890123456789012a")
        .unwrap();
    println!("decode result: {:?}", &x);
    assert_eq!(x.indices_of(Ether!()), vec![0]);
    assert_eq!(x.indices_of(Dot1Q!()), vec![1]);
    assert_eq!(x.indices_of(IP!()), vec![2]);
    assert_eq!(x.indices_of(UDP!()), vec![3]);
    let eth = &x[Ether!()];
    assert_eq!(eth.dst, "41:41:41:41:41:41".into());
    assert_eq!(eth.src, "42:42:42:42:42:42".into());
    assert_eq!(eth.etype, Value::Set(0x8100));
    let dot1q = &x[Dot1Q!()];
    assert_eq!(dot1q.vlan, Value::Set(545));

    eprintln!("{:?}", &x);
}
