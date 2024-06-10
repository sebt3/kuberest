use std::str::FromStr;

use crate::{Error, Error::*};
use actix_web::Result;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use reqwest::{Client, Response};
use rhai::{Dynamic, Map};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::runtime::Handle;
use tracing::*;

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema, Default)]
pub enum ReadMethod {
    #[default]
    Get,
}
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema, Default)]
pub enum CreateMethod {
    #[default]
    Post,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema, Default)]
pub enum UpdateMethod {
    #[default]
    Patch,
    Put,
    Post,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema, Default)]
pub enum DeleteMethod {
    #[default]
    Delete,
}

#[derive(Clone, Debug)]
pub struct RestClient {
    baseurl: String,
    headers: Map,
}

impl RestClient {
    #[must_use]
    pub fn new(base: &str) -> RestClient {
        RestClient {
            baseurl: base.to_string(),
            headers: Map::new(),
        }
    }

    pub fn baseurl(&mut self, base: &str) -> &mut RestClient {
        self.baseurl = base.to_string();
        self
    }

    pub fn baseurl_rhai(&mut self, base: String) {
        self.baseurl(base.as_str());
    }

    pub fn headers_reset(&mut self) -> &mut RestClient {
        self.headers = Map::new();
        self
    }

    pub fn headers_reset_rhai(&mut self) {
        self.headers_reset();
    }

    pub fn add_header(&mut self, key: &str, value: &str) -> &mut RestClient {
        self.headers
            .insert(key.to_string().into(), value.to_string().into());
        self
    }

    pub fn add_header_rhai(&mut self, key: String, value: String) {
        self.add_header(key.as_str(), value.as_str());
    }

    pub fn add_header_json_content(&mut self) -> &mut RestClient {
        if self
            .headers
            .clone()
            .into_iter()
            .any(|(c, _)| c == "Content-Type".to_string())
        {
            self
        } else {
            self.add_header("Content-Type", "application/json; charset=utf-8")
        }
    }

    pub fn add_header_json_accept(&mut self) -> &mut RestClient {
        for (key, val) in self.headers.clone() {
            debug!("RestClient.header: {:} {:}", key, val);
        }
        if self
            .headers
            .clone()
            .into_iter()
            .any(|(c, _)| c == "Accept".to_string())
        {
            self
        } else {
            self.add_header("Accept", "application/json")
        }
    }

    pub fn add_header_json(&mut self) {
        self.add_header_json_content().add_header_json_accept();
    }

    pub fn add_header_bearer(&mut self, token: &str) {
        self.add_header("Authorization", format!("Bearer {token}").as_str());
    }

    pub fn add_header_basic(&mut self, username: &str, password: &str) {
        let hash = STANDARD.encode(format!("{username}:{password}"));
        self.add_header("Authorization", format!("Basic {hash}").as_str());
    }

    pub fn http_get(&mut self, path: &str) -> std::result::Result<Response, reqwest::Error> {
        debug!("http_get '{}' ", format!("{}/{}", self.baseurl, path));
        let mut client = Client::new().get(format!("{}/{}", self.baseurl, path));
        for (key, val) in self.headers.clone() {
            client = client.header(key.to_string(), val.to_string());
        }
        tokio::task::block_in_place(|| Handle::current().block_on(async move { client.send().await }))
    }

    pub fn body_get(&mut self, path: &str) -> Result<String, Error> {
        let response = self
            .http_get(path)
            .or_else(|e| return Err(Error::ReqwestError(e)))?;
        if !response.status().is_success() {
            let status = response.status();
            let text = tokio::task::block_in_place(|| {
                Handle::current().block_on(async move { response.text().await })
            })
            .or_else(|e| return Err(Error::ReqwestError(e)))?;
            return Err(Error::MethodFailed(
                "Get".to_string(),
                status.as_u16(),
                format!(
                    "The server returned the error: {} {} | {text}",
                    status.as_str(),
                    status.canonical_reason().unwrap_or("unknown")
                ),
            ));
        }
        let text =
            tokio::task::block_in_place(|| Handle::current().block_on(async move { response.text().await }))
                .or_else(|e| return Err(Error::ReqwestError(e)))?;
        Ok(text)
    }

    pub fn json_get(&mut self, path: &str) -> Result<Value, Error> {
        let text = self.body_get(path).or_else(|e| return Err(e))?;
        let json = serde_json::from_str(&text).or_else(|e| return Err(Error::JsonError(e)))?;
        Ok(json)
    }

    pub fn rhai_get(&mut self, path: String) -> Map {
        let mut ret = Map::new();
        match self.http_get(path.as_str()) {
            Ok(result) => {
                ret.insert(
                    "code".to_string().into(),
                    Dynamic::from_int(result.status().as_u16().to_string().parse::<i64>().unwrap()),
                );
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        let text = result.text().await.unwrap();
                        ret.insert(
                            "json".to_string().into(),
                            serde_json::from_str(&text).unwrap_or(Dynamic::from(json!({}))),
                        );
                        ret.insert("body".to_string().into(), Dynamic::from(text));
                        ret.into()
                    })
                })
            }
            Err(e) => {
                let mut res = Map::new();
                res.insert(
                    "error".to_string().into(),
                    Dynamic::from_str(&format!("{:}", e)).unwrap(),
                );
                res
            }
        }
    }

    pub fn http_patch(&mut self, path: &str, body: &str) -> Result<Response, reqwest::Error> {
        debug!("http_patch '{}' ", format!("{}/{}", self.baseurl, path));
        let mut client = Client::new()
            .patch(format!("{}/{}", self.baseurl, path))
            .body(body.to_string());
        for (key, val) in self.headers.clone() {
            client = client.header(key.to_string(), val.to_string());
        }
        tokio::task::block_in_place(|| Handle::current().block_on(async move { client.send().await }))
    }

    pub fn body_patch(&mut self, path: &str, body: &str) -> Result<String, Error> {
        let response = self
            .http_patch(path, body)
            .or_else(|e| return Err(Error::ReqwestError(e)))?;
        if !response.status().is_success() {
            let status = response.status();
            let text = tokio::task::block_in_place(|| {
                Handle::current().block_on(async move { response.text().await })
            })
            .or_else(|e| return Err(Error::ReqwestError(e)))?;
            return Err(Error::MethodFailed(
                "Patch".to_string(),
                status.as_u16(),
                format!(
                    "The server returned the error: {} {} | {text}",
                    status.as_str(),
                    status.canonical_reason().unwrap_or("unknown")
                ),
            ));
        }
        let text =
            tokio::task::block_in_place(|| Handle::current().block_on(async move { response.text().await }))
                .or_else(|e| return Err(Error::ReqwestError(e)))?;
        Ok(text)
    }

    pub fn json_patch(&mut self, path: &str, input: &Value) -> Result<Value, Error> {
        let body = serde_json::to_string(input).or_else(|e| return Err(Error::JsonError(e)))?;
        let text = self.body_patch(path, body.as_str()).or_else(|e| return Err(e))?;
        let json = serde_json::from_str(&text).or_else(|e| return Err(Error::JsonError(e)))?;
        Ok(json)
    }

    pub fn rhai_patch(&mut self, path: String, val: Dynamic) -> Map {
        let body = if val.is_string() {
            val.to_string()
        } else {
            serde_json::to_string(&val).unwrap()
        };
        let mut ret = Map::new();
        match self.http_patch(path.as_str(), &body) {
            Ok(result) => {
                ret.insert(
                    "code".to_string().into(),
                    Dynamic::from_int(result.status().as_u16().to_string().parse::<i64>().unwrap()),
                );
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        let text = result.text().await.unwrap();
                        ret.insert(
                            "json".to_string().into(),
                            serde_json::from_str(&text).unwrap_or(Dynamic::from(json!({}))),
                        );
                        ret.insert("body".to_string().into(), Dynamic::from(text));
                        ret.into()
                    })
                })
            }
            Err(e) => {
                let mut res = Map::new();
                res.insert(
                    "error".to_string().into(),
                    Dynamic::from_str(&format!("{:}", e)).unwrap(),
                );
                res
            }
        }
    }

    pub fn http_put(&mut self, path: &str, body: &str) -> Result<Response, reqwest::Error> {
        debug!("http_put '{}' ", format!("{}/{}", self.baseurl, path));
        let mut client = Client::new()
            .put(format!("{}/{}", self.baseurl, path))
            .body(body.to_string());
        for (key, val) in self.headers.clone() {
            client = client.header(key.to_string(), val.to_string());
        }
        tokio::task::block_in_place(|| Handle::current().block_on(async move { client.send().await }))
    }

    pub fn body_put(&mut self, path: &str, body: &str) -> Result<String, Error> {
        let response = self
            .http_put(path, body)
            .or_else(|e| return Err(Error::ReqwestError(e)))?;
        if !response.status().is_success() {
            let status = response.status();
            let text = tokio::task::block_in_place(|| {
                Handle::current().block_on(async move { response.text().await })
            })
            .or_else(|e| return Err(Error::ReqwestError(e)))?;
            return Err(Error::MethodFailed(
                "Put".to_string(),
                status.as_u16(),
                format!(
                    "The server returned the error: {} {} | {text}",
                    status.as_str(),
                    status.canonical_reason().unwrap_or("unknown")
                ),
            ));
        }
        let text =
            tokio::task::block_in_place(|| Handle::current().block_on(async move { response.text().await }))
                .or_else(|e| return Err(Error::ReqwestError(e)))?;
        Ok(text)
    }

    pub fn json_put(&mut self, path: &str, input: &Value) -> Result<Value, Error> {
        let body = serde_json::to_string(input).or_else(|e| return Err(Error::JsonError(e)))?;
        let text = self.body_put(path, body.as_str()).or_else(|e| return Err(e))?;
        let json = serde_json::from_str(&text).or_else(|e| return Err(Error::JsonError(e)))?;
        Ok(json)
    }

    pub fn rhai_put(&mut self, path: String, val: Dynamic) -> Map {
        let body = if val.is_string() {
            val.to_string()
        } else {
            serde_json::to_string(&val).unwrap()
        };
        let mut ret = Map::new();
        match self.http_put(path.as_str(), &body) {
            Ok(result) => {
                ret.insert(
                    "code".to_string().into(),
                    Dynamic::from_int(result.status().as_u16().to_string().parse::<i64>().unwrap()),
                );
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        let text = result.text().await.unwrap();
                        ret.insert(
                            "json".to_string().into(),
                            serde_json::from_str(&text).unwrap_or(Dynamic::from(json!({}))),
                        );
                        ret.insert("body".to_string().into(), Dynamic::from(text));
                        ret.into()
                    })
                })
            }
            Err(e) => {
                let mut res = Map::new();
                res.insert(
                    "error".to_string().into(),
                    Dynamic::from_str(&format!("{:}", e)).unwrap(),
                );
                res
            }
        }
    }

    pub fn http_post(&mut self, path: &str, body: &str) -> Result<Response, reqwest::Error> {
        debug!("http_post '{}' ", format!("{}/{}", self.baseurl, path));
        let mut client = Client::new()
            .post(format!("{}/{}", self.baseurl, path))
            .body(body.to_string());
        for (key, val) in self.headers.clone() {
            client = client.header(key.to_string(), val.to_string());
        }
        tokio::task::block_in_place(|| Handle::current().block_on(async move { client.send().await }))
    }

    pub fn body_post(&mut self, path: &str, body: &str) -> Result<String, Error> {
        let response = self
            .http_post(path, body)
            .or_else(|e| return Err(Error::ReqwestError(e)))?;
        if !response.status().is_success() {
            let status = response.status();
            let text = tokio::task::block_in_place(|| {
                Handle::current().block_on(async move { response.text().await })
            })
            .or_else(|e| return Err(Error::ReqwestError(e)))?;
            return Err(Error::MethodFailed(
                "Post".to_string(),
                status.as_u16(),
                format!(
                    "The server returned the error: {} {} | {text}",
                    status.as_str(),
                    status.canonical_reason().unwrap_or("unknown")
                ),
            ));
        }
        let text =
            tokio::task::block_in_place(|| Handle::current().block_on(async move { response.text().await }))
                .or_else(|e| return Err(Error::ReqwestError(e)))?;
        Ok(text)
    }

    pub fn json_post(&mut self, path: &str, input: &Value) -> Result<Value, Error> {
        let body = serde_json::to_string(input).or_else(|e| return Err(Error::JsonError(e)))?;
        let text = self.body_post(path, body.as_str()).or_else(|e| return Err(e))?;
        let json = serde_json::from_str(&text).or_else(|e| return Err(Error::JsonError(e)))?;
        Ok(json)
    }

    pub fn rhai_post(&mut self, path: String, val: Dynamic) -> Map {
        let body = if val.is_string() {
            val.to_string()
        } else {
            serde_json::to_string(&val).unwrap()
        };
        let mut ret = Map::new();
        match self.http_post(path.as_str(), &body) {
            Ok(result) => {
                ret.insert(
                    "code".to_string().into(),
                    Dynamic::from_int(result.status().as_u16().to_string().parse::<i64>().unwrap()),
                );
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        let text = result.text().await.unwrap();
                        ret.insert(
                            "json".to_string().into(),
                            serde_json::from_str(&text).unwrap_or(Dynamic::from(json!({}))),
                        );
                        ret.insert("body".to_string().into(), Dynamic::from(text));
                        ret.into()
                    })
                })
            }
            Err(e) => {
                let mut res = Map::new();
                res.insert(
                    "error".to_string().into(),
                    Dynamic::from_str(&format!("{:}", e)).unwrap(),
                );
                res
            }
        }
    }

    pub fn http_delete(&mut self, path: &str) -> Result<Response, reqwest::Error> {
        debug!("http_delete '{}' ", format!("{}/{}", self.baseurl, path));
        let mut client = Client::new().delete(format!("{}/{}", self.baseurl, path));
        for (key, val) in self.headers.clone() {
            client = client.header(key.to_string(), val.to_string());
        }
        tokio::task::block_in_place(|| Handle::current().block_on(async move { client.send().await }))
    }

    pub fn body_delete(&mut self, path: &str) -> Result<String, Error> {
        let response = self
            .http_delete(path)
            .or_else(|e| return Err(Error::ReqwestError(e)))?;
        if !response.status().is_success() {
            let status = response.status();
            let text = tokio::task::block_in_place(|| {
                Handle::current().block_on(async move { response.text().await })
            })
            .or_else(|e| return Err(Error::ReqwestError(e)))?;
            return Err(Error::MethodFailed(
                "Delete".to_string(),
                status.as_u16(),
                format!(
                    "The server returned the error: {} {} | {text}",
                    status.as_str(),
                    status.canonical_reason().unwrap_or("unknown")
                ),
            ));
        }
        let text =
            tokio::task::block_in_place(|| Handle::current().block_on(async move { response.text().await }))
                .or_else(|e| return Err(Error::ReqwestError(e)))?;
        Ok(text)
    }

    pub fn json_delete(&mut self, path: &str) -> Result<Value, Error> {
        let text = self.body_delete(path).or_else(|e| return Err(e))?;
        let json = serde_json::from_str(&text).or_else(|_| return Ok(json!({"body": text})))?;
        Ok(json)
    }

    pub fn rhai_delete(&mut self, path: String) -> Map {
        let mut ret = Map::new();
        match self.http_delete(path.as_str()) {
            Ok(result) => {
                ret.insert(
                    "code".to_string().into(),
                    Dynamic::from_int(result.status().as_u16().to_string().parse::<i64>().unwrap()),
                );
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        let text = result.text().await.unwrap();
                        ret.insert(
                            "json".to_string().into(),
                            serde_json::from_str(&text).unwrap_or(Dynamic::from(json!({}))),
                        );
                        ret.insert("body".to_string().into(), Dynamic::from(text));
                        ret.into()
                    })
                })
            }
            Err(e) => {
                let mut res = Map::new();
                res.insert(
                    "error".to_string().into(),
                    Dynamic::from_str(&format!("{:}", e)).unwrap(),
                );
                res
            }
        }
    }

    pub fn obj_read(&mut self, method: ReadMethod, path: &str, key: &str) -> Result<Value, Error> {
        let full_path = if key == "" {
            path.to_string()
        } else {
            format!("{path}/{key}")
        };
        if method == ReadMethod::Get {
            self.json_get(&full_path)
        } else {
            Err(UnsupportedMethod)
        }
    }

    pub fn obj_create(&mut self, method: CreateMethod, path: &str, input: &Value) -> Result<Value, Error> {
        if method == CreateMethod::Post {
            self.json_post(path, input)
        } else {
            Err(UnsupportedMethod)
        }
    }

    pub fn obj_update(
        &mut self,
        method: UpdateMethod,
        path: &str,
        key: &str,
        input: &Value,
        use_slash: bool,
    ) -> Result<Value, Error> {
        let full_path = if key == "" {
            path.to_string()
        } else if use_slash {
            format!("{path}/{key}/")
        } else {
            format!("{path}/{key}")
        };
        if method == UpdateMethod::Patch {
            self.json_patch(&full_path, input)
        } else if method == UpdateMethod::Put {
            self.json_put(&full_path, input)
        } else if method == UpdateMethod::Post {
            self.json_post(&full_path, input)
        } else {
            Err(UnsupportedMethod)
        }
    }

    pub fn obj_delete(&mut self, method: DeleteMethod, path: &str, key: &str) -> Result<Value, Error> {
        let full_path = if key == "" {
            path.to_string()
        } else {
            format!("{path}/{key}")
        };
        if method == DeleteMethod::Delete {
            self.json_delete(&full_path)
        } else {
            Err(UnsupportedMethod)
        }
    }
}
