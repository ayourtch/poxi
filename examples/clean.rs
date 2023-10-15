use scarust::*;
use std::convert::TryFrom;

fn get_dst() -> MacAddr {
    MacAddr::from("22:22:22:22:22:22")
}

fn main() {
    let layers = Ether!(src = "00:01:02:03:04:05").dst(Value::Func(get_dst))
        / IP!(src = "192.0.2.1", dst = "2.2.2.2")
        / UDP!(sport = 1234).dport(22)
        / UDP!().dport(22)
        / "Testing123".to_string();

    println!("Layers ({}): {:#?}", layers.layers.len(), &layers);

    let udp = &layers[UDP!()];
    println!("UDP Sport: {}", udp.sport);

    println!("Set: {:?}", &layers);
    let filled = layers.fill();
    println!("Filled: {:?}", &filled);
    let bytes = filled.encode();
    println!("Encoded bytes: {:02x?}", &bytes);
}
