use std::collections::HashMap;

use crate::restendpoint::{Metadata, RestEndPoint, RESTPATH_FINALIZER};
use anyhow::{bail, Result};
use kube::{
    api::{Api, DeleteParams, ListParams, ObjectList, Patch, PatchParams, PostParams},
    Client,
};

pub use k8s_openapi::api::core::v1::Secret;
pub struct SecretHandler {
    api: Api<Secret>,
    namespace: String,
}
impl SecretHandler {
    #[must_use]
    pub fn new(cl: &Client, ns: &str) -> SecretHandler {
        SecretHandler {
            api: Api::namespaced(cl.clone(), ns),
            namespace: ns.to_string(),
        }
    }

    pub async fn list(&mut self) -> Result<ObjectList<Secret>, kube::Error> {
        let lp = ListParams::default();
        self.api.list(&lp).await
    }

    pub async fn have(&mut self, name: &str) -> bool {
        let list = self.list().await.unwrap();
        for secret in list {
            if secret.metadata.name.clone().unwrap_or_default() == name {
                return true;
            }
        }
        false
    }

    pub async fn have_uid(&mut self, name: &str, uid: &str) -> bool {
        let list = self.list().await.unwrap();
        for secret in list {
            if secret.metadata.name.clone().unwrap_or_default() == name
                && secret.metadata.uid.clone().unwrap_or_default() == uid
            {
                return true;
            }
        }
        false
    }

    pub async fn get(&mut self, name: &str) -> Result<Secret, kube::Error> {
        self.api.get(name).await
    }

    pub async fn create(
        &mut self,
        owner: Option<&RestEndPoint>,
        meta: &Metadata,
        strings: &HashMap<String, String>,
    ) -> Result<Secret, kube::Error> {
        let mut metadata = serde_json::json!({
            "name": meta.name
        });
        if let Some(own) = owner {
            // cannot flag ownership is namespace are not the same
            if own.metadata.namespace.clone().unwrap_or(self.namespace.clone()) == self.namespace {
                metadata["ownerReferences"] = serde_json::json!([{
                    "apiVersion": "kuberest.solidite.fr/v1",
                    "blockOwnerDeletion": true,
                    "controller": true,
                    "kind": "RestEndPoint",
                    "name": own.metadata.name,
                    "uid": own.metadata.uid
                }]);
            }
        }
        if let Some(labels) = meta.labels.clone() {
            metadata["labels"] = serde_json::json!(labels);
        }
        if let Some(annotations) = meta.annotations.clone() {
            metadata["annotations"] = serde_json::json!(annotations);
        }
        let secret = serde_json::from_value(serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": metadata,
            "stringData": strings
        }))
        .unwrap();
        self.api.create(&PostParams::default(), &secret).await
    }

    pub async fn update(
        &mut self,
        meta: &Metadata,
        strings: &HashMap<String, String>,
    ) -> Result<Secret, kube::Error> {
        let mut metadata = serde_json::json!({
            "name": meta.name
        });
        if let Some(labels) = meta.labels.clone() {
            metadata["labels"] = serde_json::json!(labels);
        }
        if let Some(annotations) = meta.annotations.clone() {
            metadata["annotations"] = serde_json::json!(annotations);
        }
        let params = PatchParams::apply(RESTPATH_FINALIZER).force();
        let secret = Patch::Apply(serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": metadata,
            "stringData": strings
        }));
        self.api.patch(&meta.name, &params, &secret).await
    }

    pub async fn delete(&mut self, name: &str) -> Result<()> {
        let _ = self
            .api
            .delete(name, &DeleteParams::default())
            .await
            .or_else(|e| bail!("{e:?}"));
        Ok(())
    }
}

pub use k8s_openapi::api::core::v1::ConfigMap;
pub struct ConfigMapHandler {
    api: Api<ConfigMap>,
    namespace: String,
}
impl ConfigMapHandler {
    #[must_use]
    pub fn new(cl: &Client, ns: &str) -> ConfigMapHandler {
        ConfigMapHandler {
            api: Api::namespaced(cl.clone(), ns),
            namespace: ns.to_string(),
        }
    }

    pub async fn list(&mut self) -> Result<ObjectList<ConfigMap>, kube::Error> {
        let lp = ListParams::default();
        self.api.list(&lp).await
    }

    pub async fn have(&mut self, name: &str) -> bool {
        let list = self.list().await.unwrap();
        for cm in list {
            if cm.metadata.name.clone().unwrap_or_default() == name {
                return true;
            }
        }
        false
    }

    pub async fn have_uid(&mut self, name: &str, uid: &str) -> bool {
        let list = self.list().await.unwrap();
        for cm in list {
            if cm.metadata.name.clone().unwrap_or_default() == name
                && cm.metadata.uid.clone().unwrap_or_default() == uid
            {
                return true;
            }
        }
        false
    }

    pub async fn get(&mut self, name: &str) -> Result<ConfigMap, kube::Error> {
        self.api.get(name).await
    }

    pub async fn create(
        &mut self,
        owner: Option<&RestEndPoint>,
        meta: &Metadata,
        data: &HashMap<String, String>,
    ) -> Result<ConfigMap, kube::Error> {
        let mut metadata = serde_json::json!({
            "name": meta.name
        });
        if let Some(own) = owner {
            // cannot flag ownership is namespace are not the same
            if own.metadata.namespace.clone().unwrap_or(self.namespace.clone()) == self.namespace {
                metadata["ownerReferences"] = serde_json::json!([{
                    "apiVersion": "kuberest.solidite.fr/v1",
                    "blockOwnerDeletion": true,
                    "controller": true,
                    "kind": "RestEndPoint",
                    "name": own.metadata.name,
                    "uid": own.metadata.uid
                }]);
            }
        }
        if let Some(labels) = meta.labels.clone() {
            metadata["labels"] = serde_json::json!(labels);
        }
        if let Some(annotations) = meta.annotations.clone() {
            metadata["annotations"] = serde_json::json!(annotations);
        }
        let cm = serde_json::from_value(serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": metadata,
            "data": data
        }))
        .unwrap();
        self.api.create(&PostParams::default(), &cm).await
    }

    pub async fn update(
        &mut self,
        meta: &Metadata,
        data: &HashMap<String, String>,
    ) -> Result<ConfigMap, kube::Error> {
        let mut metadata = serde_json::json!({
            "name": meta.name
        });
        if let Some(labels) = meta.labels.clone() {
            metadata["labels"] = serde_json::json!(labels);
        }
        if let Some(annotations) = meta.annotations.clone() {
            metadata["annotations"] = serde_json::json!(annotations);
        }
        let params = PatchParams::apply(RESTPATH_FINALIZER).force();
        let cm = Patch::Apply(serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": metadata,
            "data": data
        }));
        self.api.patch(&meta.name, &params, &cm).await
    }

    pub async fn delete(&mut self, name: &str) -> Result<()> {
        let _ = self
            .api
            .delete(name, &DeleteParams::default())
            .await
            .or_else(|e| bail!("{e:?}"));
        Ok(())
    }
}
