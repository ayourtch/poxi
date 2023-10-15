#[test]
fn it_works() {
    use scarust::*;
    let ip = Ip {
        ..Default::default()
    };
    eprintln!("{:?}", ip);
    assert_eq!(2 + 2, 4);
}
