#[test]
fn decode_test_1() {
    use scarust::*;

    let x = Ether!()
        .decode("AAAAAABBBBBB\x08\x00\x452345678901234567890123456789012a".as_bytes())
        .unwrap();
    println!("decode result: {:?}", &x);
    assert_eq!(x.indices_of(Ether!()), vec![0]);
    assert_eq!(x.indices_of(IP!()), vec![1]);
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
