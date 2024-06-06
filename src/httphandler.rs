use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json,Value};
use rhai::Map;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use reqwest::{Client,Response};
use tokio::runtime::Handle;
use tracing::*;
use crate::{Error::*,Error};

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
        warn!("HTTP_GET {}",format!("{}/{}",self.baseurl,path));
        let mut client = Client::new().get(format!("{}/{}",self.baseurl,path));
        for (key,val) in self.headers {
            client = client.header(key.to_string(), val.to_string());
        }
        tokio::task::block_in_place(|| {Handle::current().block_on(async move {
            client.send().await
        })})
    }
    pub fn body_get(self, path:&str) -> Result<String,Error> {
        let response = self.http_get(path).or_else(|e| return Err(Error::ReqwestError(e)))?;
        if ! response.status().is_success() {
            return Err(Error::MethodFailed("Get".to_string(), format!("The server returned the error: {} {}",response.status().as_str(),response.status().canonical_reason().unwrap_or("unknown"))));
        }
        let text = tokio::task::block_in_place(|| {Handle::current().block_on(async move {response.text().await})}).or_else(|e| return Err(Error::ReqwestError(e)))?;
        Ok(text)
    }
    pub fn json_get(self, path:&str) -> Result<Value,Error> {
        let text = self.body_get(path).or_else(|e| return Err(e))?;
        let json = serde_json::from_str(&text).or_else(|e| return Err(Error::JsonError(e)))?;
        Ok(json)
    }
    pub fn http_patch(self, path:&str, body: &str) -> Result<Response, reqwest::Error> {
        let mut client = Client::new().patch(format!("{}/{}",self.baseurl,path)).body(body.to_string());
        for (key,val) in self.headers {
            client = client.header(key.to_string(), val.to_string());
        }
        tokio::task::block_in_place(|| {Handle::current().block_on(async move {
            client.send().await
        })})
    }
    pub fn body_patch(self, path:&str, body: &str) -> Result<String, Error> {
        let response = self.http_patch(path,body).or_else(|e| return Err(Error::ReqwestError(e)))?;
        if ! response.status().is_success() {
            return Err(Error::MethodFailed("Patch".to_string(), format!("The server returned the error: {} {}",response.status().as_str(),response.status().canonical_reason().unwrap_or("unknown"))));
        }
        let text = tokio::task::block_in_place(|| {Handle::current().block_on(async move {response.text().await})}).or_else(|e| return Err(Error::ReqwestError(e)))?;
        Ok(text)
    }
    pub fn json_patch(self, path:&str, input: &Value) -> Result<Value,Error> {
        let body = serde_json::to_string(input).or_else(|e| return Err(Error::JsonError(e)))?;
        let text = self.body_patch(path,body.as_str()).or_else(|e| return Err(e))?;
        let json = serde_json::from_str(&text).or_else(|e| return Err(Error::JsonError(e)))?;
        Ok(json)
    }
    pub fn http_put(self, path:&str, body: &str) -> Result<Response, reqwest::Error> {
        let mut client = Client::new().put(format!("{}/{}",self.baseurl,path)).body(body.to_string());
        for (key,val) in self.headers {
            client = client.header(key.to_string(), val.to_string());
        }
        tokio::task::block_in_place(|| {Handle::current().block_on(async move {
            client.send().await
        })})
    }
    pub fn body_put(self, path:&str, body: &str) -> Result<String, Error> {
        let response = self.http_put(path,body).or_else(|e| return Err(Error::ReqwestError(e)))?;
        if ! response.status().is_success() {
            return Err(Error::MethodFailed("Put".to_string(), format!("The server returned the error: {} {}",response.status().as_str(),response.status().canonical_reason().unwrap_or("unknown"))));
        }
        let text = tokio::task::block_in_place(|| {Handle::current().block_on(async move {response.text().await})}).or_else(|e| return Err(Error::ReqwestError(e)))?;
        Ok(text)
    }
    pub fn json_put(self, path:&str, input: &Value) -> Result<Value,Error> {
        let body = serde_json::to_string(input).or_else(|e| return Err(Error::JsonError(e)))?;
        let text = self.body_put(path,body.as_str()).or_else(|e| return Err(e))?;
        let json = serde_json::from_str(&text).or_else(|e| return Err(Error::JsonError(e)))?;
        Ok(json)
    }
    pub fn http_post(self, path:&str, body: &str) -> Result<Response, reqwest::Error> {
        let mut client = Client::new().post(format!("{}/{}",self.baseurl,path)).body(body.to_string());
        for (key,val) in self.headers {
            client = client.header(key.to_string(), val.to_string());
        }
        tokio::task::block_in_place(|| {Handle::current().block_on(async move {
            client.send().await
        })})
    }
    pub fn body_post(self, path:&str, body: &str) -> Result<String, Error> {
        let response = self.http_patch(path,body).or_else(|e| return Err(Error::ReqwestError(e)))?;
        if ! response.status().is_success() {
            return Err(Error::MethodFailed("Post".to_string(), format!("The server returned the error: {} {}",response.status().as_str(),response.status().canonical_reason().unwrap_or("unknown"))));
        }
        let text = tokio::task::block_in_place(|| {Handle::current().block_on(async move {response.text().await})}).or_else(|e| return Err(Error::ReqwestError(e)))?;
        Ok(text)
    }
    pub fn json_post(self, path:&str, input: &Value) -> Result<Value,Error> {
        let body = serde_json::to_string(input).or_else(|e| return Err(Error::JsonError(e)))?;
        let text = self.body_post(path,body.as_str()).or_else(|e| return Err(e))?;
        let json = serde_json::from_str(&text).or_else(|e| return Err(Error::JsonError(e)))?;
        Ok(json)
    }
    pub fn http_delete(self, path:&str) -> Result<Response, reqwest::Error> {
        let mut client = Client::new().delete(format!("{}/{}",self.baseurl,path));
        for (key,val) in self.headers {
            client = client.header(key.to_string(), val.to_string());
        }
        tokio::task::block_in_place(|| {Handle::current().block_on(async move {
            client.send().await
        })})
    }
    pub fn body_delete(self, path:&str) -> Result<String,Error> {
        let response = self.http_delete(path).or_else(|e| return Err(Error::ReqwestError(e)))?;
        if ! response.status().is_success() {
            return Err(Error::MethodFailed("Get".to_string(), format!("The server returned the error: {} {}",response.status().as_str(),response.status().canonical_reason().unwrap_or("unknown"))));
        }
        let text = tokio::task::block_in_place(|| {Handle::current().block_on(async move {response.text().await})}).or_else(|e| return Err(Error::ReqwestError(e)))?;
        Ok(text)
    }
    pub fn json_delete(self, path:&str) -> Result<Value,Error> {
        let text = self.body_delete(path).or_else(|e| return Err(e))?;
        let json = serde_json::from_str(&text).or_else(|e| return Err(Error::JsonError(e)))?;
        Ok(json)
    }

    pub fn obj_read(self, method:ReadMethod, path: &str, key:&str) -> Result<Value,Error> {
        let full_path = if key=="" {path.to_string()} else {format!("{path}/{key}")};
        if method == ReadMethod::Get {
            self.json_get(&full_path)
        } else {
            Err(UnsupportedMethod)
        }
    }
    pub fn obj_create(self, method:CreateMethod, path: &str, input: &Value) -> Result<Value,Error> {
        if method == CreateMethod::Post {
            self.json_post(path, input)
        } else {
            Err(UnsupportedMethod)
        }

    }
    pub fn obj_update(self, method:UpdateMethod, path: &str, key:&str, input:&Value) -> Result<Value,Error> {
        let full_path = if key=="" {path.to_string()} else {format!("{path}/{key}")};
        if method == UpdateMethod::Patch {
            self.json_patch(&full_path, input)
        } else if method == UpdateMethod::Post {
            self.json_post(&full_path, input)
        } else if method == UpdateMethod::Put {
            self.json_put(&full_path, input)
        } else {
            Err(UnsupportedMethod)
        }
    }
    pub fn obj_delete(self, method:DeleteMethod, path: &str, key:&str) -> Result<Value,Error> {
        let full_path = if key=="" {path.to_string()} else {format!("{path}/{key}")};
        if method == DeleteMethod::Delete {
            self.json_delete(&full_path)
        } else {
            Err(UnsupportedMethod)
        }
    }
}
