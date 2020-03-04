use relay_general::pii::*;

fn main() {
    loop {
        let mut cfgs = vec![];

        for _ in 0..10000 {
            let cfg = DataScrubbingConfig {
                scrub_data: true,
                scrub_ip_addresses: true,
                scrub_defaults: true,
                ..Default::default()
            };
            cfgs.push(cfg.pii_config());
        }
    }
}
