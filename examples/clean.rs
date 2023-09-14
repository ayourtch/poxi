use scarust::*;
use std::convert::TryFrom;

fn main() {
    let layers = IP!(src = "1.1.1.1", dst = "2.2.2.2") / UDP!(sport = 1234).dport(22);
    println!("Layers: {:#?}", &layers);

    let udp = &layers[UDP!()];
    println!("UDP Sport: {}", udp.sport);
}
