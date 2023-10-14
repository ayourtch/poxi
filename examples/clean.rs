use scarust::*;
use std::convert::TryFrom;

fn main() {
    let layers = ETHER!(src = "00:01:02:03:04:05")
        / IP!(src = "1.1.1.1", dst = "2.2.2.2")
        / UDP!(sport = 1234).dport(22)
        / UDP!().dport(22);
    println!("Layers: {:#?}", &layers);

    let udp = &layers[UDP!()];
    println!("UDP Sport: {}", udp.sport);
    println!("Encoded bytes: {:02x?}", layers.fill().encode());
}
