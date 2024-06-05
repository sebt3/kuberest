use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json,Value};
use rhai::Map;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use reqwest::{Client,Response};
use tokio::runtime::Handle;
use anyhow::{Result,bail};
use tracing::*;

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema, Default)]
pub enum ReadMethod {
    #[default]
    Get
}
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema, Default)]
pub enum CreateMethod {
    #[default]
    Post
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema, Default)]
pub enum UpdateMethod {
    #[default]
    Patch,
    Put,
    Post
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema, Default)]
pub enum DeleteMethod {
    #[default]
    Delete
}

#[derive(Clone, Debug)]
pub struct RestClient {
    baseurl: String,
    headers: Map,
}

impl RestClient {
    #[must_use] pub fn new(base: &str) -> RestClient {
        RestClient {
            baseurl: base.to_string(),
            headers: Map::new()
        }
    }
    pub fn add_header(mut self, key:&str, value: &str) -> RestClient {
        self.headers.insert(key.to_string().into(),value.to_string().into());
        self
    }
    pub fn add_header_json_content(self) -> RestClient {
        if self.headers.clone().into_iter().any(|(c,_)| c == "Content-Type".to_string()) {
            self
        }else {
            self.add_header("Content-Type", "application/json; charset=utf-8")
        }
    }
    pub fn add_header_json_accept(self) -> RestClient {
        for (key,val) in self.headers.clone() {
            debug!("RestClient.header: {:} {:}",key,val);
        }
        if self.headers.clone().into_iter().any(|(c,_)| c == "Accept".to_string()) {
            self
        }else {
            self.add_header("Accept", "application/json")
        }
    }
    pub fn add_header_json(self) -> RestClient {
        self.add_header_json_content().add_header_json_accept()
    }
    pub fn add_header_bearer(self, token:&str) -> RestClient {
        self.add_header("Authorization", format!("Bearer {token}").as_str())
    }
    pub fn add_header_basic(self, username: &str, password: &str) -> RestClient {
        let hash = STANDARD.encode(format!("{username}:{password}"));
        self.add_header("Authorization", format!("Basic {hash}").as_str())
    }
    pub fn http_get(self, path:&str) -> std::result::Result<Response, reqwest::Error> {
        let mut client = Client::new().get(format!("{}/{}",self.baseurl,path));
        for (key,val) in self.headers {
            client = client.header(key.to_string(), val.to_string());
        }
        tokio::task::block_in_place(|| {Handle::current().block_on(async move {
            client.send().await
        })})
    }
    pub fn http_patch(self, path:&str, body: &str) -> std::result::Result<Response, reqwest::Error> {
        let mut client = Client::new().patch(format!("{}/{}",self.baseurl,path)).body(body.to_string());
        for (key,val) in self.headers {
            client = client.header(key.to_string(), val.to_string());
        }
        tokio::task::block_in_place(|| {Handle::current().block_on(async move {
            client.send().await
        })})
    }
    pub fn http_put(self, path:&str, body: &str) -> std::result::Result<Response, reqwest::Error> {
        let mut client = Client::new().put(format!("{}/{}",self.baseurl,path)).body(body.to_string());
        for (key,val) in self.headers {
            client = client.header(key.to_string(), val.to_string());
        }
        tokio::task::block_in_place(|| {Handle::current().block_on(async move {
            client.send().await
        })})
    }
    pub fn http_delete(self, path:&str) -> std::result::Result<Response, reqwest::Error> {
        let mut client = Client::new().delete(format!("{}/{}",self.baseurl,path));
        for (key,val) in self.headers {
            client = client.header(key.to_string(), val.to_string());
        }
        tokio::task::block_in_place(|| {Handle::current().block_on(async move {
            client.send().await
        })})
    }
    pub fn obj_list(self, path: &str) {
        let res = self.http_get(path);

    }
    pub fn obj_read(self, method:ReadMethod, path: &str, key:&str) -> Result<Value> {
        if method == ReadMethod::Get {
            // TODO xD
            Ok(json!({}))
        } else {
            bail!("unsupported method")
        }
    }
    pub fn obj_create(self, method:CreateMethod, path: &str, object:Value) -> Result<Value> {
        if method == CreateMethod::Post {
            // TODO xD
            Ok(json!({}))
        } else {
            bail!("unsupported method")
        }

    }
    pub fn obj_update(self, method:UpdateMethod, path: &str, object:Value) -> Result<Value> {
        if method == UpdateMethod::Patch {
            // TODO xD
            Ok(json!({}))
        } else if method == UpdateMethod::Post {
            // TODO xD
            Ok(json!({}))
        } else if method == UpdateMethod::Put {
            // TODO xD
            Ok(json!({}))
        } else {
            bail!("unsupported method")
        }
    }
    pub fn obj_delete(self, method:DeleteMethod, path: &str, key:&str) -> Result<Value> {
        if method == DeleteMethod::Delete {
            // TODO xD
            Ok(json!({}))
        } else {
            bail!("unsupported method")
        }
    }
}
