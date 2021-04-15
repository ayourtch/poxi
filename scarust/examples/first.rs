use scarust::Ip;
use scarust::Layer;
use scarust::LayerStack;
use scarust::Udp;
use std::any::Any;
use std::any::TypeId;

fn main() {
    let ip = Ip::default();
    let udp = Udp::default();

    let layers3 = ip.clone().to_stack() / udp.clone().to_stack();

    let layers = ip / udp.clone() / udp.clone();
    let layers2 = layers.clone();

    println!("{:#?}", &layers);
    println!("{:#?}", &layers3);

    let ip_type = TypeId::of::<Ip>();
    let udp_type = TypeId::of::<Udp>();

    for node in layers.layers {
        println!(
            "ip: {} udp: {}",
            node.type_id_is(ip_type),
            node.type_id_is(udp_type)
        );
    }
}
