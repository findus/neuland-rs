extern crate iptables;

fn main() {
    println!("Hello, world!");
    let ipt = iptables::new(false).unwrap();
    ipt.append("mangle", "PREROUTING", "-s 0.0.0.0/24  -i eth0 -p udp --match multiport ! --dports 443,1301 --j MARK --set-mark 1").unwrap();
    ipt.list("mangle", "PREROUTING").unwrap().iter().for_each(|e| println!("{}", e));
}
