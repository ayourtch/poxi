use scarust::Ip;
use scarust::Layer;
use scarust::LayerStack;
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

fn main() {
    let ip = Ip::default();
    let udp = Udp::default();

    let mut ip = IP!(
        src = [1, 1, 1, 1],
        dst = [2, 2, 2, 22],
        id = 12u16,
        ttl = 32
    );

    let layers3 = IP!() / udp.clone();

    let layers = ip.version(5).id(22).src([1, 1, 1, 1].into()) / udp.clone() / udp.clone();
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
