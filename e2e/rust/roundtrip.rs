//! E2E live round-trip for the Rust SDK. Builds a real sketch per fixed route via the SDK's own
//! build_sketch, prints the shape hash, then POSTs the batch to the LIVE sketches endpoint.
use nemesis_shield::Client;

fn main() {
    let token = std::env::var("NEMESIS_TOKEN").unwrap_or_default();
    let c = Client::new(token.clone());
    let routes = [
        ("GET", "/app/incidents/inc_ip_1_2_3_4_1786400000000"),
        ("GET", "/app/network/autogon.ai"),
        ("GET", "/app/applications/f47ac10b-58cc-4372-a567-0e02b2c3d479"),
    ];
    let mut items: Vec<String> = Vec::new();
    for (method, path) in routes {
        let s = c.build_sketch(method, path, &[], false, 200);
        println!("SHAPE {} route={} hash={}", path, s.route, s.shape);
        items.push(format!(
            "{{\"route\":\"{}\",\"method\":\"{}\",\"authenticated\":false,\"status\":200,\"params\":[],\"shape\":\"{}\"}}",
            s.route, s.method, s.shape
        ));
    }
    let body = format!("{{\"sketches\":[{}]}}", items.join(","));
    let resp = ureq::post("https://shield.nemesislabs.xyz/api/v1/sketches")
        .set("Authorization", &format!("Bearer {}", token))
        .set("Content-Type", "application/json")
        .send_string(&body);
    match resp {
        Ok(r) => println!("POST_STATUS {}", r.status()),
        Err(ureq::Error::Status(code, _)) => println!("POST_STATUS {}", code),
        Err(e) => println!("POST_STATUS ERR {}", e),
    }
}
