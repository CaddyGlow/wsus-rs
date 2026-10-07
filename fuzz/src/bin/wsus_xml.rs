#[allow(dead_code)]
#[path = "../wsus.rs"]
mod wsus;

fn main() {
    loop {
        honggfuzz::fuzz!(|data: &[u8]| {
            wsus::run("wsus_xml", data).expect("known target");
        });
    }
}
