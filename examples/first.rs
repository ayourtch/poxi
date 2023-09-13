use scarust::Ip;
use scarust::Layer;
use scarust::LayerStack;
use scarust::New;
use scarust::Udp;
use std::any::Any;
use std::any::TypeId;

macro_rules! IP {
    () => {{
        {
            let mut ip: Ip = Default::default();
            ip
        }
    }};

    ($ip:ident, $ident:ident=$e:expr) => {{
        {
            $ip.$ident = $e.into();
        }
    }};
    ($ip: ident, $ident:ident=$e:expr, $($x_ident:ident=$es:expr),+) => {{
        {
            IP!($ip, $ident=$e);
            IP!($ip, $($x_ident=$es),+);
        }
    }};

    ($ident:ident=$e:expr) => {{
        {
            let mut ip: Ip = Default::default();
            IP!(ip, $ident=$e);
            ip
        }
    }};
    ($ident:ident=$e:expr, $($s_ident:ident=$es:expr),+) => {{
        {
            let mut ip = IP!($ident=$e);
            IP!(ip, $($s_ident=$es),+);
            ip
        }
    }};

}

use scarust::FromStringHashmap;
use std::collections::HashMap;

fn main() {
    let ip = Ip::default();
    let udp = Udp::default();

    let mut ip = IP!(
        src = [1, 1, 1, 1],
        dst = [2, 2, 2, 22],
        id = 12u16,
        ttl = 32
    );

    let mut hip: HashMap<String, String> = HashMap::new();

    hip.insert("src".into(), "1.1.1.1".into());
    hip.insert("dst".into(), "1.2.3.4".into());
    hip.insert("chksum".into(), "1234".into());

    ip = Ip::from_string_hashmap(hip);
    println!("first ip {:#?}", &ip);

    let layers3 = IP!() / udp.clone();

    let layers =
        Ip::new().version(5).id(22).src([1, 1, 1, 1]).dst("2.2.2.2") / Udp::new() / Udp::new();
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
