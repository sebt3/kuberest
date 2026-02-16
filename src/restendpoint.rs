use crate::{
    Error, Metrics, Result, create,
    handlebarshandler::HandleBars,
    httphandler::{CreateMethod, DeleteMethod, ReadMethod, RestClient, UpdateMethod},
    k8shandlers::{ConfigMapHandler, SecretHandler},
    passwordhandler::Passwords,
    rhaihandler::Script,
    telemetry, template, update,
};
use chrono::{self, DateTime, Utc};
use futures::StreamExt;
use k8s_openapi::api::core::v1::{Namespace, ObjectReference};
use kube::{
    CustomResource, Resource,
    api::{Api, ListParams, Patch, PatchParams, ResourceExt},
    client::Client,
    runtime::{
        controller::{Action, Controller},
        events::{Event, EventType, Recorder, Reporter},
        finalizer::{Event as Finalizer, finalizer},
        watcher::Config,
    },
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_json_path::JsonPath;
use std::{collections::HashMap, sync::Arc};
use tokio::{runtime::Handle, sync::RwLock, time::Duration};
use tracing::*;

pub static RESTPATH_FINALIZER: &str = "restendpoints.kuberest.solidite.fr";
pub fn get_client_name() -> String {
    RESTPATH_FINALIZER.to_string()
}

/// ConfigMapRef describe a data input for handlebars renders from a ConfigMap
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema)]
pub struct ConfigMapRef {
    /// Name of the ConfigMap
    pub name: String,
    /// Namespace of the ConfigMap, only used if the cross-namespace option is enabled (default: current object namespace)
    pub namespace: Option<String>,
    /// Is the ConfigMap requiered for processing ? (default: false)
    pub optional: Option<bool>,
}

/// SecretRef describe a data input for handlebars renders from a Secret
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema)]
pub struct SecretRef {
    /// Name of the Secret
    pub name: String,
    /// Namespace of the Secret, only used if the cross-namespace option is enabled (default: current object namespace)
    pub namespace: Option<String>,
    /// Is the Secret optional for processing ? (default: false)
    pub optional: Option<bool>,
}

/// randomPassword describe the rules to generate a password
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RandomPassword {
    /// length of the password (default: 32)
    pub length: Option<u32>,
    /// weight of alpha caracters (default: 60)
    pub weight_alphas: Option<u32>,
    /// weight of numbers caracters (default: 20)
    pub weight_numbers: Option<u32>,
    /// weight of symbols caracters (default: 20)
    pub weight_symbols: Option<u32>,
}

// TODO: ssh-key (priv+pub) as input (for secret generation)

/// inputItem describe a data input for handlebars renders
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct InputItem {
    /// name of the input (used for handlebars renders)
    pub name: String,
    /// The ConfigMap to select from
    pub config_map_ref: Option<ConfigMapRef>,
    /// The Secret to select from
    pub secret_ref: Option<SecretRef>,
    /// an handlebars template to be rendered
    pub handle_bars_render: Option<String>,
    /// A password generator
    pub password_generator: Option<RandomPassword>,
}

/// templateItem describe a list of handlebars templates that will be registered with given name
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TemplateItem {
    /// name of the input (used for handlebars renders)
    pub name: String,
    /// The template to register
    pub template: String,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct WebClient {
    /// The baseurl the client will use. All path will use this as a prefix
    pub baseurl: String,
    /// Headers to use on each requests to the endpoint
    pub headers: Option<HashMap<String, String>>,
    /// keyName: the key of the object (default: id)
    pub key_name: Option<String>,
    /// Method to use when creating an object (default: Get)
    pub create_method: Option<CreateMethod>,
    /// Method to use when reading an object (default: Post)
    pub read_method: Option<ReadMethod>,
    /// Method to use when updating an object (default: Put)
    pub update_method: Option<UpdateMethod>,
    /// Method to use when deleting an object (default: Delete)
    pub delete_method: Option<DeleteMethod>,
    /// Delete the Objects on RestEndPoint deletion (default: true, inability to do so will block RestEndPoint)
    teardown: Option<bool>,
    /// For self-signed Certificates on the destination endpoint
    pub server_ca: Option<String>,
    /// mTLS client key
    pub client_key: Option<String>,
    /// mTLS client certificate
    pub client_cert: Option<String>,
    /// If true, updates and deletes use the same path as create and include the primary key in the payload (default: false)
    pub children_no_sub_key: Option<bool>,
}
impl Default for WebClient {
    fn default() -> Self {
        WebClient {
            baseurl: "http://localhost:8080".to_string(),
            headers: None,
            key_name: Some("id".to_string()),
            create_method: Some(CreateMethod::Post),
            read_method: Some(ReadMethod::Get),
            update_method: Some(UpdateMethod::Put),
            delete_method: Some(DeleteMethod::Delete),
            teardown: Some(true),
            server_ca: None,
            client_cert: None,
            client_key: None,
            children_no_sub_key: Some(false),
        }
    }
}

/// readGroupItem describe an object to read with the client
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema)]
pub struct ReadGroupItem {
    /// name of the item (used for handlebars renders)
    pub name: String,
    /// configuration of this object
    pub key: String,
    /// Allow missing object (default false)
    pub optional: Option<bool>,
    /// Get the result from a json-query
    pub json_query: Option<String>,
}
/// ReadGroup describe a rest endpoint within the client sub-paths,
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema)]
pub struct ReadGroup {
    /// name of the write (used for handlebars renders)
    pub name: String,
    /// path appended to the client's baseurl for this group of objects
    pub path: String,
    /// Method to use when reading an object (default: Get)
    pub read_method: Option<ReadMethod>,
    /// The list of object mapping
    pub items: Vec<ReadGroupItem>,
}

/// writeGroupItem describe an object to maintain within
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct WriteGroupItem {
    /// name of the item (used for handlebars renders: write.<group>.<name>)
    pub name: String,
    /// configuration of this object (yaml format, use handlebars to generate your needed values)
    pub values: String,
    /// Delete the Object on RestEndPoint deletion (default: true, inability to do so will block RestEndPoint)
    pub teardown: Option<bool>,
    /// If writes doesnt return values, use this read query to re-read
    pub read_path: Option<String>,
    /// If writes doesnt return values, (only used when readPath is specified too)
    pub read_json_query: Option<String>,
}
/// writeGroup describe a rest endpoint within the client sub-paths,
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct WriteGroup {
    /// name of the write (used for handlebars renders: write.<name>)
    pub name: String,
    /// path appended to the client's baseurl for this group of objects
    pub path: String,
    /// keyName: the key of the object (default: id)
    pub key_name: Option<String>,
    /// keyUseSlash: should the update/delete url end with a slash at the end (default: false)
    pub key_use_slash: Option<bool>,
    /// Method to use when creating an object (default: Post)
    pub create_method: Option<CreateMethod>,
    /// Method to use when reading an object (default: Get)
    pub read_method: Option<ReadMethod>,
    /// Method to use when updating an object (default: Patch)
    pub update_method: Option<UpdateMethod>,
    /// Path to use to update/delete this write_group
    pub update_path: Option<String>,
    /// Method to use when deleting an object (default: Delete)
    pub delete_method: Option<DeleteMethod>,
    /// The list of object mapping
    pub items: Vec<WriteGroupItem>,
    /// Delete the Objects on RestEndPoint deletion (default: true, inability to do so will block RestEndPoint)
    teardown: Option<bool>,
    /// If true, updates and deletes use the same path as create and include the primary key in the payload (default: client value or false)
    pub children_no_sub_key: Option<bool>,
}

/// metadata describe a rest endpoint within the client sub-paths
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema)]
pub struct Metadata {
    /// name of the created object
    pub name: String,
    /// namespace of the created object
    pub namespace: Option<String>,
    /// labels of the objects
    pub labels: Option<HashMap<String, String>>,
    /// annotations of the objects
    pub annotations: Option<HashMap<String, String>>,
}
impl Default for Metadata {
    fn default() -> Self {
        Metadata {
            name: "default".to_string(),
            namespace: None,
            labels: None,
            annotations: None,
        }
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema, Default)]
pub enum Kind {
    #[default]
    Secret,
    ConfigMap,
}

/// outputItem describe an object that will be created/updated after the path objects are all handled
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct OutputItem {
    /// Either ConfigMap or Secret
    kind: Kind,
    /// The metadata of the Object (requiered: name)
    metadata: Metadata,
    /// Data of the Output (will be base64-encoded for secret Secrets)
    data: HashMap<String, String>,
    /// Delete the Secret on RestEndPoint deletion (default: true)
    teardown: Option<bool>,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema, Default)]
pub enum ConditionsType {
    #[default]
    Ready,
    InputMissing,
    InputFailed,
    TemplateFailed,
    InitScriptFailed,
    PreScriptFailed,
    PostScriptFailed,
    TeardownScriptFailed,
    ReadFailed,
    ReadMissing,
    ReReadFailed,
    WriteFailed,
    WriteDeleteFailed,
    WriteAlreadyExist,
    OutputFailed,
    OutputDeleteFailed,
    OutputAlreadyExist,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema, Default)]
pub enum ConditionsStatus {
    #[default]
    True,
    False,
}

/// ApplicationCondition contains details about an application condition, which is usually an error or warning
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationCondition {
    /// LastTransitionTime is the time the condition was last observed
    pub last_transition_time: Option<DateTime<Utc>>,
    /// Message contains human-readable message indicating details about condition
    pub message: String,
    /// Type is an application condition type
    #[serde(rename = "type")]
    pub condition_type: ConditionsType,
    /// Status ("True" or "False") describe if the condition is enbled
    pub status: ConditionsStatus,
}
impl ApplicationCondition {
    #[must_use]
    pub fn new(
        message: &str,
        status: ConditionsStatus,
        condition_type: ConditionsType,
    ) -> ApplicationCondition {
        ApplicationCondition {
            last_transition_time: Some(chrono::offset::Utc::now()),
            status,
            condition_type,
            message: message.to_string(),
        }
    }

    pub fn input_missing(message: &str) -> ApplicationCondition {
        ApplicationCondition::new(message, ConditionsStatus::True, ConditionsType::InputMissing)
    }

    pub fn output_exist(message: &str) -> ApplicationCondition {
        ApplicationCondition::new(
            message,
            ConditionsStatus::True,
            ConditionsType::OutputAlreadyExist,
        )
    }

    pub fn init_script_failed(message: &str) -> ApplicationCondition {
        ApplicationCondition::new(message, ConditionsStatus::True, ConditionsType::InitScriptFailed)
    }

    pub fn pre_script_failed(message: &str) -> ApplicationCondition {
        ApplicationCondition::new(message, ConditionsStatus::True, ConditionsType::PreScriptFailed)
    }

    pub fn post_script_failed(message: &str) -> ApplicationCondition {
        ApplicationCondition::new(message, ConditionsStatus::True, ConditionsType::PostScriptFailed)
    }

    pub fn teardown_script_failed(message: &str) -> ApplicationCondition {
        ApplicationCondition::new(
            message,
            ConditionsStatus::True,
            ConditionsType::TeardownScriptFailed,
        )
    }

    pub fn write_exist(message: &str) -> ApplicationCondition {
        ApplicationCondition::new(message, ConditionsStatus::True, ConditionsType::WriteAlreadyExist)
    }

    pub fn input_failed(message: &str) -> ApplicationCondition {
        ApplicationCondition::new(message, ConditionsStatus::True, ConditionsType::InputFailed)
    }

    pub fn template_failed(message: &str) -> ApplicationCondition {
        ApplicationCondition::new(message, ConditionsStatus::True, ConditionsType::TemplateFailed)
    }

    pub fn read_missing(message: &str) -> ApplicationCondition {
        ApplicationCondition::new(message, ConditionsStatus::True, ConditionsType::ReadMissing)
    }

    pub fn read_failed(message: &str) -> ApplicationCondition {
        ApplicationCondition::new(message, ConditionsStatus::True, ConditionsType::ReadFailed)
    }

    pub fn write_failed(message: &str) -> ApplicationCondition {
        ApplicationCondition::new(message, ConditionsStatus::True, ConditionsType::WriteFailed)
    }

    pub fn reread_failed(message: &str) -> ApplicationCondition {
        ApplicationCondition::new(message, ConditionsStatus::True, ConditionsType::ReReadFailed)
    }

    pub fn write_delete_failed(message: &str) -> ApplicationCondition {
        ApplicationCondition::new(message, ConditionsStatus::True, ConditionsType::WriteDeleteFailed)
    }

    pub fn output_failed(message: &str) -> ApplicationCondition {
        ApplicationCondition::new(message, ConditionsStatus::True, ConditionsType::OutputFailed)
    }

    pub fn output_delete_failed(message: &str) -> ApplicationCondition {
        ApplicationCondition::new(
            message,
            ConditionsStatus::True,
            ConditionsType::OutputDeleteFailed,
        )
    }

    pub fn is_ready(message: &str) -> ApplicationCondition {
        ApplicationCondition::new(message, ConditionsStatus::True, ConditionsType::Ready)
    }

    pub fn not_ready(message: &str) -> ApplicationCondition {
        ApplicationCondition::new(message, ConditionsStatus::False, ConditionsType::Ready)
    }
}

/// List all owned k8s objects
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct OwnedObjects {
    /// Either ConfigMap or Secret
    pub kind: Kind,
    /// name of the owned object
    pub name: String,
    /// namespace of the owned object
    pub namespace: String,
    /// uid of the owned object
    pub uid: String,
}
impl OwnedObjects {
    #[must_use]
    pub fn new(kind: Kind, name: &str, namespace: &str, uid: &str) -> OwnedObjects {
        OwnedObjects {
            kind,
            name: name.to_string(),
            namespace: namespace.to_string(),
            uid: uid.to_string(),
        }
    }

    pub fn secret(name: &str, namespace: &str, uid: &str) -> OwnedObjects {
        OwnedObjects::new(Kind::Secret, name, namespace, uid)
    }

    pub fn configmap(name: &str, namespace: &str, uid: &str) -> OwnedObjects {
        OwnedObjects::new(Kind::ConfigMap, name, namespace, uid)
    }
}

/// List all owned rest objects
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct OwnedRestPoint {
    /// Object path within the client
    pub path: String,
    /// Object key
    pub key: String,
    /// Object writeGroup
    pub group: String,
    /// Object name within its writeGroup
    pub name: String,
    /// should we manage this object deletion
    pub teardown: bool,
    /// If true, deletes include the key in the payload instead of the URL
    pub children_no_sub_key: Option<bool>,
    /// Key field name used for payload construction (default: id)
    pub key_name: Option<String>,
}
impl OwnedRestPoint {
    #[must_use]
    pub fn new(
        path: &str,
        key: &str,
        group: &str,
        name: &str,
        teardown: bool,
        children_no_sub_key: bool,
        key_name: &str,
    ) -> OwnedRestPoint {
        OwnedRestPoint {
            path: path.to_string(),
            key: key.to_string(),
            group: group.to_string(),
            name: name.to_string(),
            teardown,
            children_no_sub_key: Some(children_no_sub_key),
            key_name: Some(key_name.to_string()),
        }
    }
}

/// Describe the specification of a RestEndPoint
#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[cfg_attr(test, derive(Default))]
#[kube(
    kind = "RestEndPoint",
    group = "kuberest.solidite.fr",
    version = "v1",
    namespaced,
    status = "RestEndPointStatus",
    shortname = "rep"
)]
#[kube(
    doc = "Custom resource representing a RestEndPoint for kuberest",
    printcolumn = r#"
    {"name":"baseurl",   "type":"string", "description":"Base URL", "jsonPath":".spec.client.baseurl"},
    {"name":"last_updated", "type":"date", "description":"Last update date", "format": "date-time", "jsonPath":".status.conditions[?(@.type == 'Ready')].lastTransitionTime"},
    {"name":"errors", "type":"string", "description":"Errors", "jsonPath":".status.conditions[?(@.status == 'False')].message"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct RestEndPointSpec {
    /// List Handlebars templates to register
    pub templates: Option<Vec<TemplateItem>>,
    /// List input source for Handlebars renders
    pub inputs: Option<Vec<InputItem>>,
    /// A rhai pre-script to setup some complex variables before client setup
    pub init: Option<String>,
    /// Define the how the client should connect to the API endpoint(s)
    pub client: WebClient,
    /// A rhai pre-script to setup some complex variables
    pub pre: Option<String>,
    /// Allow to read some pre-existing objects
    pub reads: Option<Vec<ReadGroup>>,
    /// Sub-paths to the client. Allow to describe the objects to create on the end-point
    pub writes: Option<Vec<WriteGroup>>,
    /// A rhai post-script for final validation if any
    pub post: Option<String>,
    /// Objects (Secret or ConfigMap) to create at the end of the process
    pub outputs: Option<Vec<OutputItem>>,
    /// checkFrequency define the pooling interval (in seconds, default: 3600 aka 1h)
    pub check_frequency: Option<u64>,
    /// retryFrequency define the pooling interval if previous try have failed (in seconds, default: 300 aka 5mn)
    pub retry_frequency: Option<u64>,
    /// A rhai teardown-script for a final cleanup on RestEndPoint deletion
    pub teardown: Option<String>,
}
/// The status object of `RestEndPoint`
#[derive(Deserialize, Serialize, Clone, Default, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RestEndPointStatus {
    pub conditions: Vec<ApplicationCondition>,
    pub owned: Vec<OwnedObjects>,
    pub owned_target: Vec<OwnedRestPoint>,
    pub generation: i64,
}

// Context for our reconciler
#[derive(Clone)]
pub struct Context {
    /// Kubernetes client
    pub client: Client,
    /// Diagnostics read by the web server
    pub diagnostics: Arc<RwLock<Diagnostics>>,
    /// Prometheus metrics
    pub metrics: Metrics,
}

#[instrument(skip(ctx, rest_path), fields(trace_id))]
async fn reconcile(rest_path: Arc<RestEndPoint>, ctx: Arc<Context>) -> Result<Action> {
    let trace_id = telemetry::get_trace_id();
    Span::current().record("trace_id", field::display(&trace_id));
    let _timer = ctx.metrics.count_and_measure();
    ctx.diagnostics.write().await.last_event = Utc::now();
    let ns = rest_path.namespace().unwrap();
    let paths: Api<RestEndPoint> = Api::namespaced(ctx.client.clone(), &ns);

    info!("Reconciling RestEndPoint \"{}\" in {}", rest_path.name_any(), ns);
    finalizer(&paths, RESTPATH_FINALIZER, rest_path, |event| async {
        match event {
            Finalizer::Apply(rest_path) => rest_path.reconcile(ctx.clone()).await,
            Finalizer::Cleanup(rest_path) => rest_path.cleanup(ctx.clone()).await,
        }
    })
    .await
    .map_err(|e| Error::FinalizerError(Box::new(e)))
}

fn error_policy(restendpoint: Arc<RestEndPoint>, error: &Error, ctx: Arc<Context>) -> Action {
    warn!("reconcile failed: {:?}", error);
    ctx.metrics.reconcile_failure(&restendpoint, error);
    Action::requeue(Duration::from_secs(5 * 60))
}

impl RestEndPoint {
    fn owned(&self) -> Vec<OwnedObjects> {
        if let Some(st) = self.status.clone() {
            st.owned
        } else {
            Vec::new()
        }
    }

    fn owned_target(&self) -> Vec<OwnedRestPoint> {
        if let Some(st) = self.status.clone() {
            st.owned_target
        } else {
            Vec::new()
        }
    }

    async fn publish(
        recorder: &Recorder,
        obj_ref: &ObjectReference,
        reason: String,
        note_p: String,
        action: String,
    ) -> Result<()> {
        let mut note = note_p;
        note.truncate(1023);
        match recorder
            .publish(
                &Event {
                    type_: EventType::Normal,
                    reason,
                    note: Some(note),
                    action,
                    secondary: None,
                },
                obj_ref,
            )
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => match e {
                kube::Error::Api(src) => {
                    if !src
                        .message
                        .as_str()
                        .contains("unable to create new content in namespace")
                        || !src.message.as_str().contains("being terminated")
                    {
                        tracing::warn!("Ignoring {:?} while sending an event", src);
                    }
                    Ok(())
                }
                _ => Err(Error::KubeError(e)),
            },
        }
    }

    async fn publish_warning(
        recorder: &Recorder,
        obj_ref: &ObjectReference,
        reason: String,
        note_p: String,
        action: String,
    ) -> Result<()> {
        let mut note = note_p;
        note.truncate(1023);
        match recorder
            .publish(
                &Event {
                    type_: EventType::Warning,
                    reason,
                    note: Some(note),
                    action,
                    secondary: None,
                },
                obj_ref,
            )
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => match e {
                kube::Error::Api(src) => {
                    if !src
                        .message
                        .as_str()
                        .contains("unable to create new content in namespace")
                        || !src.message.as_str().contains("being terminated")
                    {
                        tracing::warn!("Ignoring {:?} while sending an event", src);
                    }
                    Ok(())
                }
                _ => Err(Error::KubeError(e)),
            },
        }
    }

    async fn get_tenant_namespaces(&self, client: Client) -> Result<Vec<String>> {
        let my_ns = self.metadata.namespace.clone().unwrap();
        let ns_api: Api<Namespace> = Api::all(client);
        let my_ns_meta = ns_api.get_metadata(&my_ns).await.map_err(Error::KubeError)?;
        let label_key =
            std::env::var("TENANT_LABEL").unwrap_or_else(|_| "kuberest.solidite.fr/tenant".to_string());
        let res = vec![my_ns];
        if let Some(labels) = my_ns_meta.metadata.labels.clone()
            && labels.clone().keys().any(|k| k == &label_key)
        {
            let tenant_name = &labels[&label_key];
            let mut lp = ListParams::default();
            lp = lp.labels(format!("{}=={}", label_key, tenant_name).as_str());
            let my_nss = ns_api.list_metadata(&lp).await.map_err(Error::KubeError)?;
            return Ok(my_nss
                .items
                .into_iter()
                .map(|n| n.metadata.name.unwrap())
                .collect());
        }
        Ok(res)
    }

    // Reconcile (for non-finalizer related changes)
    async fn reconcile(&self, ctx: Arc<Context>) -> Result<Action> {
        // Before everything : is this reconcillation because of our last status update ?
        if let Some(status) = self.status.clone() {
            let now = chrono::offset::Utc::now();
            if status.generation == self.metadata.generation.unwrap_or(1) {
                let delta: u64 = (now - status.conditions[0].last_transition_time.unwrap_or(now))
                    .num_seconds()
                    .try_into()
                    .unwrap();
                if status
                    .conditions
                    .into_iter()
                    .any(|c| c.status == ConditionsStatus::False && c.condition_type == ConditionsType::Ready)
                {
                    let next = self.spec.retry_frequency.unwrap_or(5 * 60);
                    if delta < next {
                        debug!(
                            "The spec didnt change, only the status (which this code just did), waiting {} more secs",
                            next - delta
                        );
                        return Ok(Action::requeue(Duration::from_secs(next - delta)));
                    }
                } else {
                    let next = self.spec.check_frequency.unwrap_or(60 * 60);
                    if next > 0 {
                        if delta < next {
                            debug!(
                                "The spec didnt change, only the status (which this code just did), waiting {} more secs",
                                next - delta
                            );
                            return Ok(Action::requeue(Duration::from_secs(next - delta)));
                        }
                    } else {
                        warn!("No spec change, should have awaited change. Will do.");
                        return Ok(Action::await_change());
                    }
                }
            }
        }

        let client = ctx.client.clone();
        let recorder = ctx.diagnostics.read().await.recorder(client.clone());
        let obj_ref = self.object_ref(&());
        let ns = self.namespace().unwrap();
        let name = self.name_any();
        let restendpoints: Api<RestEndPoint> = Api::namespaced(client.clone(), &ns);
        let mut conditions: Vec<ApplicationCondition> = Vec::new();
        let mut values = serde_json::json!({"input":{},"pre":{},"read":{},"write":{},"post":{}});
        let mut hbs = HandleBars::new();
        if let Some(templates) = self.spec.templates.clone() {
            for item in templates {
                hbs.register_template(&item.name, &item.template)
                    .unwrap_or_else(|e| {
                        conditions.push(ApplicationCondition::template_failed(&format!(
                            "Registering template.{} raised {e:?}",
                            item.name
                        )));
                    });
            }
        }
        let mut rhai = Script::new();
        rhai.ctx.set_or_push("hbs", hbs.clone());
        let use_multi = std::env::var("MULTI_TENANT")
            .unwrap_or_else(|_| "true".to_string())
            .to_lowercase()
            == *"true";
        let allowed = if use_multi && (self.spec.inputs.is_some() || self.spec.outputs.is_some()) {
            self.get_tenant_namespaces(client.clone()).await?
        } else {
            Vec::new()
        };

        // Read the inputs first
        if let Some(inputs) = self.spec.clone().inputs {
            for input in inputs {
                if let Some(secret) = input.secret_ref {
                    let my_ns = if use_multi {
                        if let Some(o_ns) = secret.namespace.clone() {
                            if allowed.contains(&o_ns) {
                                o_ns
                            } else {
                                Self::publish_warning(&recorder, &obj_ref, String::from("IgnoredNamespace"), format!("Ignoring namespace from Input '{}' as the operator run in multi-tenant mode",input.name), String::from("readingInput")).await?;
                                ns.clone()
                            }
                        } else {
                            ns.clone()
                        }
                    } else if let Some(local_ns) = secret.namespace {
                        local_ns
                    } else {
                        ns.clone()
                    };
                    let mut secrets = SecretHandler::new(&ctx.client.clone(), &my_ns);
                    if secrets.have(&secret.name).await {
                        let my_secret = secrets.get(&secret.name).await.unwrap();
                        values["input"][input.name] = serde_json::json!({
                            "metadata": my_secret.metadata,
                            "data": my_secret.data
                        });
                    } else if secret.optional.unwrap_or(false) {
                        Self::publish(
                            &recorder,
                            &obj_ref,
                            String::from("IgnoredInput"),
                            format!("Ignoring not found secret for Input '{}'", input.name),
                            String::from("readingInput"),
                        )
                        .await?;
                        conditions.push(ApplicationCondition::input_missing(&format!(
                            "Input '{}' Secret {}.{} not found",
                            input.name, my_ns, secret.name
                        )));
                        values["input"][input.name] = serde_json::json!({});
                    } else {
                        Self::publish(
                            &recorder,
                            &obj_ref,
                            String::from("MissingSecret"),
                            format!("Secret '{}' not found for Input '{}'", secret.name, input.name),
                            String::from("readingInput"),
                        )
                        .await?;
                        conditions.push(ApplicationCondition::input_failed(&format!(
                            "Input '{}' Secret {}.{} not found",
                            input.name, my_ns, secret.name
                        )));
                    }
                } else if let Some(cfgmap) = input.config_map_ref {
                    let my_ns = if use_multi {
                        if let Some(o_ns) = cfgmap.namespace.clone() {
                            if allowed.contains(&o_ns) {
                                o_ns
                            } else {
                                Self::publish_warning(&recorder, &obj_ref, String::from("IgnoredNamespace"), format!("Ignoring namespace from Input '{}' as the operator run in multi-tenant mode",input.name), String::from("readingInput")).await?;
                                ns.clone()
                            }
                        } else {
                            ns.clone()
                        }
                    } else if let Some(local_ns) = cfgmap.namespace {
                        local_ns
                    } else {
                        ns.clone()
                    };
                    let mut maps = ConfigMapHandler::new(&ctx.client.clone(), &my_ns);
                    if maps.have(&cfgmap.name).await {
                        let my_cfg = maps.get(&cfgmap.name).await.unwrap();
                        values["input"][input.name] = serde_json::json!({
                            "metadata": my_cfg.metadata,
                            "data": my_cfg.data,
                            "binaryData": my_cfg.binary_data
                        });
                    } else if cfgmap.optional.unwrap_or(false) {
                        Self::publish(
                            &recorder,
                            &obj_ref,
                            String::from("IgnoredInput"),
                            format!("Ignoring not found ConfigMap for Input '{}'", input.name),
                            String::from("readingInput"),
                        )
                        .await?;
                        conditions.push(ApplicationCondition::input_missing(&format!(
                            "Input '{}' ConfigMap {}.{} not found",
                            input.name, my_ns, cfgmap.name
                        )));
                        values["input"][input.name] = serde_json::json!({});
                    } else {
                        Self::publish(
                            &recorder,
                            &obj_ref,
                            String::from("MissingConfigMap"),
                            format!("ConfigMap '{}' not found for Input '{}'", cfgmap.name, input.name),
                            String::from("readingInput"),
                        )
                        .await?;
                        conditions.push(ApplicationCondition::input_failed(&format!(
                            "Input '{}' ConfigMap {}.{} not found",
                            input.name, my_ns, cfgmap.name
                        )));
                    }
                } else if let Some(render) = input.handle_bars_render {
                    values["input"][input.name] = json!(template!(
                        render.as_str(),
                        hbs,
                        &values,
                        conditions,
                        recorder,
                        &obj_ref
                    ));
                } else if let Some(password_def) = input.password_generator {
                    values["input"][input.name] = json!(Passwords::new().generate(
                        password_def.length.unwrap_or(32),
                        password_def.weight_alphas.unwrap_or(60),
                        password_def.weight_numbers.unwrap_or(20),
                        password_def.weight_symbols.unwrap_or(20)
                    ));
                } else {
                    Self::publish_warning(
                        &recorder,
                        &obj_ref,
                        String::from("EmptyInput"),
                        format!("Input '{}' have no source", input.name),
                        String::from("fail"),
                    )
                    .await?;
                    conditions.push(ApplicationCondition::input_failed(&format!(
                        "Input '{}' have no source",
                        input.name
                    )));
                    conditions.push(ApplicationCondition::not_ready(&format!(
                        "Input '{}' have no source",
                        input.name
                    )));
                    let new_status = Patch::Apply(json!({
                        "apiVersion": "kuberest.solidite.fr/v1",
                        "kind": "RestEndPoint",
                        "status": RestEndPointStatus { conditions, generation: self.metadata.generation.unwrap_or(1), owned: self.owned(), owned_target: self.owned_target() }
                    }));
                    let ps = PatchParams::apply(RESTPATH_FINALIZER).force();
                    let _o = restendpoints
                        .patch_status(&name, &ps, &new_status)
                        .await
                        .map_err(Error::KubeError)?;
                    return Err(Error::IllegalRestEndPoint);
                }
            }
        }
        // Validate that reading went Ok
        if conditions
            .iter()
            .any(|c| c.condition_type != ConditionsType::InputMissing)
        {
            let msg = "Some input failed";
            Self::publish_warning(
                &recorder,
                &obj_ref,
                String::from(msg),
                format!("Found {} error(s) while handling input", conditions.len()),
                String::from("fail"),
            )
            .await?;
            conditions.push(ApplicationCondition::not_ready(msg));
            let new_status = Patch::Apply(json!({
                "apiVersion": "kuberest.solidite.fr/v1",
                "kind": "RestEndPoint",
                "status": RestEndPointStatus { conditions, generation: self.metadata.generation.unwrap_or(1), owned: self.owned(), owned_target: self.owned_target() }
            }));
            let first_run = self.status.is_none();
            let ps = PatchParams::apply(RESTPATH_FINALIZER).force();
            let _o = restendpoints
                .patch_status(&name, &ps, &new_status)
                .await
                .map_err(Error::KubeError)?;
            // Some missing Secret or ConfigMap might be ok on first run, dont wait too much
            if first_run {
                return Ok(Action::requeue(Duration::from_secs(60)));
            } else {
                return Ok(Action::requeue(Duration::from_secs(
                    self.spec.retry_frequency.unwrap_or(5 * 60),
                )));
            }
        }
        rhai.set_dynamic("input", &values["input"]);
        rhai.set_dynamic("values", &values);

        // Run the init script
        if let Some(script) = self.spec.init.clone() {
            let cnd = conditions.clone();
            values["init"] = rhai.eval(&script).unwrap_or_else(|e| {
                conditions.push(ApplicationCondition::init_script_failed(&format!("{e:?}")));
                json!({})
            });
            // Validate that init-script went Ok
            if cnd
                .iter()
                .any(|c| c.condition_type != ConditionsType::InputMissing)
            {
                let msg = "Init-script failed";
                Self::publish_warning(
                    &recorder,
                    &obj_ref,
                    String::from(msg),
                    format!("Found {} error(s) running the init-script", conditions.len()),
                    String::from("fail"),
                )
                .await?;
                conditions.push(ApplicationCondition::not_ready(msg));
                let new_status = Patch::Apply(json!({
                    "apiVersion": "kuberest.solidite.fr/v1",
                    "kind": "RestEndPoint",
                    "status": RestEndPointStatus { conditions, generation: self.metadata.generation.unwrap_or(1), owned: self.owned(), owned_target: self.owned_target() }
                }));
                let ps = PatchParams::apply(RESTPATH_FINALIZER).force();
                let _o = restendpoints
                    .patch_status(&name, &ps, &new_status)
                    .await
                    .map_err(Error::KubeError)?;
                return Ok(Action::requeue(Duration::from_secs(
                    self.spec.retry_frequency.unwrap_or(5 * 60),
                )));
            }
        }
        rhai.set_dynamic("init", &values["init"]);
        rhai.set_dynamic("values", &values);

        // Setup the httpClient
        let mut rest = RestClient::new(&template!(
            self.spec.client.baseurl.clone().as_str(),
            hbs,
            &values,
            conditions,
            recorder,
            &obj_ref
        ));
        if let Some(headers) = self.spec.client.headers.clone() {
            for (key, value) in headers {
                rest.add_header(
                    &template!(key.as_str(), hbs, &values, conditions, recorder, &obj_ref),
                    &template!(value.as_str(), hbs, &values, conditions, recorder, &obj_ref),
                );
            }
        }
        rest.add_header_json();
        if let Some(ca) = self.spec.client.server_ca.clone() {
            rest.set_server_ca(&template!(
                &ca.as_str(),
                hbs,
                &values,
                conditions,
                recorder,
                &obj_ref
            ));
        }
        if self.spec.client.client_cert.is_some() && self.spec.client.client_key.is_some() {
            rest.set_mtls(
                &template!(
                    &self.spec.client.client_cert.clone().unwrap().as_str(),
                    hbs,
                    &values,
                    conditions,
                    recorder,
                    &obj_ref
                ),
                &template!(
                    &self.spec.client.client_key.clone().unwrap().as_str(),
                    hbs,
                    &values,
                    conditions,
                    recorder,
                    &obj_ref
                ),
            );
        }
        // Validate that client setup went Ok
        let cnd = conditions.clone();
        if cnd
            .iter()
            .any(|c| c.condition_type != ConditionsType::InputMissing)
        {
            let msg = "Client setup failed";
            Self::publish_warning(
                &recorder,
                &obj_ref,
                String::from(msg),
                format!("Found {} error(s) while setting up the client", conditions.len()),
                String::from("fail"),
            )
            .await?;
            conditions.push(ApplicationCondition::not_ready(msg));
            let new_status = Patch::Apply(json!({
                "apiVersion": "kuberest.solidite.fr/v1",
                "kind": "RestEndPoint",
                "status": RestEndPointStatus { conditions, generation: self.metadata.generation.unwrap_or(1), owned: self.owned(), owned_target: self.owned_target() }
            }));
            let ps = PatchParams::apply(RESTPATH_FINALIZER).force();
            let _o = restendpoints
                .patch_status(&name, &ps, &new_status)
                .await
                .map_err(Error::KubeError)?;
            return Ok(Action::requeue(Duration::from_secs(
                self.spec.retry_frequency.unwrap_or(5 * 60),
            )));
        }
        rhai.ctx.set_or_push("client", rest.clone());

        // Run the pre script
        if let Some(script) = self.spec.pre.clone() {
            let cnd = conditions.clone();
            values["pre"] = rhai.eval(&script).unwrap_or_else(|e| {
                conditions.push(ApplicationCondition::pre_script_failed(&format!("{e:?}")));
                json!({})
            });
            // Validate that pre-script went Ok
            if cnd
                .iter()
                .any(|c| c.condition_type != ConditionsType::InputMissing)
            {
                let msg = "Pre-script failed";
                Self::publish_warning(
                    &recorder,
                    &obj_ref,
                    String::from(msg),
                    format!("Found {} error(s) running the pre-script", conditions.len()),
                    String::from("fail"),
                )
                .await?;
                conditions.push(ApplicationCondition::not_ready(msg));
                let new_status = Patch::Apply(json!({
                    "apiVersion": "kuberest.solidite.fr/v1",
                    "kind": "RestEndPoint",
                    "status": RestEndPointStatus { conditions, generation: self.metadata.generation.unwrap_or(1), owned: self.owned(), owned_target: self.owned_target() }
                }));
                let ps = PatchParams::apply(RESTPATH_FINALIZER).force();
                let _o = restendpoints
                    .patch_status(&name, &ps, &new_status)
                    .await
                    .map_err(Error::KubeError)?;
                return Ok(Action::requeue(Duration::from_secs(
                    self.spec.retry_frequency.unwrap_or(5 * 60),
                )));
            }
        }
        rhai.set_dynamic("pre", &values["pre"]);
        rhai.set_dynamic("values", &values);

        // Handle each Reads
        if let Some(reads) = self.spec.reads.clone() {
            for group in reads {
                values["read"][group.name.clone()] = serde_json::json!({});
                let path = template!(group.path.as_str(), hbs, &values, conditions, recorder, &obj_ref);
                for read in group.items {
                    let result =
                        rest.clone()
                            .obj_read(
                                group.read_method.clone().unwrap_or(
                                    self.spec.client.read_method.clone().unwrap_or(ReadMethod::Get),
                                ),
                                path.as_str(),
                                &template!(read.key.as_str(), hbs, &values, conditions, recorder, &obj_ref),
                            )
                            .unwrap_or_else(|e| {
                                if read.optional.unwrap_or(false) {
                                    conditions.push(ApplicationCondition::read_missing(&format!(
                                        "Reading read.{}.{} raised {e:?}",
                                        group.name.clone(),
                                        read.name
                                    )));
                                } else {
                                    conditions.push(ApplicationCondition::read_failed(&format!(
                                        "Reading read.{}.{} raised {e:?}",
                                        group.name.clone(),
                                        read.name
                                    )));
                                }
                                json!({})
                            });
                    let mut obj = result.clone();
                    if let Some(json_path) = read.json_query {
                        let _ = JsonPath::parse(&json_path).map(|path| {
                            obj = path
                                .query(&result)
                                .at_most_one()
                                .unwrap_or(Some(&result))
                                .unwrap_or(&result)
                                .clone();
                        });
                    }
                    values["read"][group.name.clone()][read.name] = obj;
                }
            }
        }
        // Validate that all reads went Ok
        let cnd = conditions.clone();
        if cnd.iter().any(|c| {
            c.condition_type != ConditionsType::InputMissing
                && c.condition_type != ConditionsType::ReadMissing
        }) {
            let msg = "Some read have failed";
            Self::publish_warning(
                &recorder,
                &obj_ref,
                String::from(msg),
                format!("Found {} error(s) while reading values", conditions.len()),
                String::from("fail"),
            )
            .await?;
            conditions.push(ApplicationCondition::not_ready(msg));
            let first_run = self.status.is_none();
            let new_status = Patch::Apply(json!({
                "apiVersion": "kuberest.solidite.fr/v1",
                "kind": "RestEndPoint",
                "status": RestEndPointStatus { conditions, generation: self.metadata.generation.unwrap_or(1), owned: self.owned(), owned_target: self.owned_target() }
            }));
            let ps = PatchParams::apply(RESTPATH_FINALIZER).force();
            let _o = restendpoints
                .patch_status(&name, &ps, &new_status)
                .await
                .map_err(Error::KubeError)?;
            // We might be trying to configure an app no yet from the same installation, dont wait too much on first try
            if first_run {
                return Ok(Action::requeue(Duration::from_secs(60)));
            } else {
                return Ok(Action::requeue(Duration::from_secs(
                    self.spec.retry_frequency.unwrap_or(5 * 60),
                )));
            }
        }
        rhai.set_dynamic("read", &values["read"]);
        rhai.set_dynamic("values", &values);

        // Handle each Writes
        let mut target_new: Vec<OwnedRestPoint> = Vec::new();
        let mut failures: i32 = 0;
        if let Some(writes) = self.spec.writes.clone() {
            for group in writes {
                let key_name = group
                    .key_name
                    .unwrap_or(self.spec.client.key_name.clone().unwrap_or("id".to_string()));
                let children_no_sub_key = group
                    .children_no_sub_key
                    .unwrap_or(self.spec.client.children_no_sub_key.unwrap_or(false));
                values["write"][group.name.clone()] = serde_json::json!({});
                let path = template!(group.path.as_str(), hbs, &values, conditions, recorder, &obj_ref);
                for item in group.items {
                    let cur_len = conditions.len();
                    let vals = serde_yaml::from_str(
                        template!(item.values.as_str(), hbs, &values, conditions, recorder, &obj_ref)
                            .as_str(),
                    )
                    .unwrap_or_else(|e| {
                        conditions.push(ApplicationCondition::write_failed(&format!(
                            "Templating write.{}.{}.values \n{}\nusing values: \n{}\nraised {e:?}",
                            group.name.clone(),
                            item.name,
                            item.values.as_str(),
                            serde_yaml::to_string(&values).unwrap_or_default()
                        )));
                        json!({})
                    });
                    let mut giveup = false;
                    if conditions.len() == cur_len {
                        let key = if self
                            .owned_target()
                            .clone()
                            .into_iter()
                            .any(|t| t.group == group.name && t.name == item.name)
                        {
                            // Update the object
                            let myself = self
                                .owned_target()
                                .clone()
                                .into_iter()
                                .find(|t| t.group == group.name && t.name == item.name)
                                .unwrap();
                            if myself.key.is_empty() {
                                conditions.push(ApplicationCondition::write_failed(&format!(
                                    "Will *not* update write.{}.{} with an empty key",
                                    group.name.clone(),
                                    item.name
                                )));
                                "".to_string()
                            } else {
                                let (update_path, update_key, update_vals) = if children_no_sub_key {
                                    let mut merged = vals.clone();
                                    merged[key_name.clone()] = json!(myself.key);
                                    (path.clone(), "".to_string(), merged)
                                } else {
                                    (
                                        group.update_path.clone().unwrap_or(path.clone()),
                                        myself.key.clone(),
                                        vals.clone(),
                                    )
                                };
                                let mut obj = rest
                                    .clone()
                                    .obj_update(
                                        group.update_method.clone().unwrap_or(
                                            self.spec
                                                .client
                                                .update_method
                                                .clone()
                                                .unwrap_or(UpdateMethod::Patch),
                                        ),
                                        update_path.as_str(),
                                        &update_key,
                                        &update_vals,
                                    )
                                    .unwrap_or_else(|e| {
                                        giveup = if let Error::MethodFailed(_, code, _) = e {
                                            code == 404
                                        } else {
                                            false
                                        };
                                        match e {
                                            Error::JsonError(_) => {
                                                if item.read_path.is_none() {
                                                    conditions.push(ApplicationCondition::write_failed(
                                                        &format!(
                                                            "Updating write.{}.{} raised {e:?}",
                                                            group.name.clone(),
                                                            item.name
                                                        ),
                                                    ));
                                                }
                                            }
                                            _ => {
                                                conditions.push(ApplicationCondition::write_failed(
                                                    &format!(
                                                        "Updating write.{}.{} raised {e:?}",
                                                        group.name.clone(),
                                                        item.name
                                                    ),
                                                ));
                                            }
                                        }
                                        json!({})
                                    });
                                if let Some(read_path) = item.read_path.clone() {
                                    let my_read = rest
                                        .clone()
                                        .obj_read(
                                            group.read_method.clone().unwrap_or(
                                                self.spec
                                                    .client
                                                    .read_method
                                                    .clone()
                                                    .unwrap_or(ReadMethod::Get),
                                            ),
                                            read_path.as_str(),
                                            "",
                                        )
                                        .unwrap_or_else(|e| {
                                            conditions.push(ApplicationCondition::reread_failed(&format!(
                                                "Reading back write.{}.{} raised {e:?}",
                                                group.name.clone(),
                                                item.name
                                            )));
                                            json!({})
                                        });
                                    obj = my_read.clone();
                                    if let Some(json_path) = item.read_json_query.clone() {
                                        let _ = JsonPath::parse(&json_path).map(|path| {
                                            obj = path
                                                .query(&my_read)
                                                .at_most_one()
                                                .unwrap_or(Some(&my_read))
                                                .unwrap_or(&my_read)
                                                .clone();
                                        });
                                    }
                                }
                                values["write"][group.name.clone()][item.name.clone()] = obj.clone();
                                let key_name_moved = key_name.clone();
                                if obj[key_name.clone()].is_i64() {
                                    obj[key_name.clone()].as_i64().unwrap().to_string()
                                } else if obj[key_name.clone()].is_u64() {
                                    obj[key_name.clone()].as_u64().unwrap().to_string()
                                } else if obj[key_name.clone()].is_number() {
                                    obj[key_name.clone()].as_number().unwrap().to_string()
                                } else {
                                    obj[key_name.clone()].as_str().unwrap_or_else(|| {
                                        conditions.push(ApplicationCondition::write_failed(&format!("While updating write.{}.{} {} is neither a number or a string in {:}",group.name.clone(),item.name,key_name_moved,obj)));
                                        ""
                                    }).to_string()
                                }
                            }
                        } else {
                            // Create the object
                            let tmp = format!("{path}/");
                            let my_path = if group.key_use_slash.unwrap_or(false) {
                                tmp.as_str()
                            } else {
                                path.as_str()
                            };
                            let mut obj = rest
                                .clone()
                                .obj_create(
                                    group.create_method.clone().unwrap_or(
                                        self.spec
                                            .client
                                            .create_method
                                            .clone()
                                            .unwrap_or(CreateMethod::Post),
                                    ),
                                    my_path,
                                    &vals,
                                )
                                .unwrap_or_else(|e| {
                                    match e {
                                        Error::JsonError(_) => {
                                            if item.read_path.is_none() {
                                                conditions.push(ApplicationCondition::write_failed(
                                                    &format!(
                                                        "Creating write.{}.{} raised {e:?}",
                                                        group.name.clone(),
                                                        item.name
                                                    ),
                                                ));
                                            }
                                        }
                                        _ => {
                                            conditions.push(ApplicationCondition::write_failed(&format!(
                                                "Creating write.{}.{} raised {e:?}",
                                                group.name.clone(),
                                                item.name
                                            )));
                                        }
                                    }
                                    json!({})
                                });
                            if let Some(read_path) = item.read_path.clone() {
                                let my_read = rest
                                    .clone()
                                    .obj_read(
                                        group.read_method.clone().unwrap_or(
                                            self.spec.client.read_method.clone().unwrap_or(ReadMethod::Get),
                                        ),
                                        read_path.as_str(),
                                        "",
                                    )
                                    .unwrap_or_else(|e| {
                                        conditions.push(ApplicationCondition::reread_failed(&format!(
                                            "Reading back write.{}.{} raised {e:?}",
                                            group.name.clone(),
                                            item.name
                                        )));
                                        json!({})
                                    });
                                obj = my_read.clone();
                                if let Some(json_path) = item.read_json_query.clone() {
                                    let _ = JsonPath::parse(&json_path).map(|path| {
                                        obj = path
                                            .query(&my_read)
                                            .at_most_one()
                                            .unwrap_or(Some(&my_read))
                                            .unwrap_or(&my_read)
                                            .clone();
                                    });
                                }
                            }
                            values["write"][group.name.clone()][item.name.clone()] = obj.clone();
                            let key_name_moved = key_name.clone();
                            if obj[key_name.clone()].is_i64() {
                                obj[key_name.clone()].as_i64().unwrap().to_string()
                            } else if obj[key_name.clone()].is_u64() {
                                obj[key_name.clone()].as_u64().unwrap().to_string()
                            } else if obj[key_name.clone()].is_number() {
                                obj[key_name.clone()].as_number().unwrap().to_string()
                            } else {
                                obj[key_name.clone()].as_str().unwrap_or_else(|| {
                                    conditions.push(ApplicationCondition::write_failed(&format!("While creating write.{}.{} {} is neither a number or a string in {:}",group.name.clone(),item.name,key_name_moved,obj)));
                                    ""
                                }).to_string()
                            }
                        };
                        if !giveup && !key.is_empty() {
                            let tmp = format!("{key}/");
                            let my_key = if group.key_use_slash.unwrap_or(false) {
                                tmp.as_str()
                            } else {
                                key.as_str()
                            };
                            let owned_path = if children_no_sub_key {
                                path.clone()
                            } else {
                                group.update_path.clone().unwrap_or(path.clone())
                            };
                            target_new.push(OwnedRestPoint::new(
                                owned_path.as_str(),
                                my_key,
                                group.name.as_str(),
                                item.name.as_str(),
                                item.teardown.unwrap_or(
                                    group
                                        .teardown
                                        .unwrap_or(self.spec.client.teardown.unwrap_or(true)),
                                ),
                                children_no_sub_key,
                                key_name.as_str(),
                            ));
                        } else if giveup {
                            failures += 1;
                        }
                    }
                }
            }
        }
        // Delete old owned writes if no failures
        if failures == 0 {
            for old in self.owned_target().clone() {
                if old.teardown
                    && !target_new
                        .clone()
                        .into_iter()
                        .any(|t| t.group == old.group && t.name == old.name)
                {
                    let delete_result = if old.children_no_sub_key.unwrap_or(false) {
                        let del_key_name = old.key_name.clone().unwrap_or("id".to_string());
                        rest.obj_delete_with_body(
                            DeleteMethod::Delete,
                            &old.path,
                            &json!({del_key_name: old.key}),
                        )
                    } else {
                        rest.obj_delete(DeleteMethod::Delete, &old.path, &old.key)
                    };
                    delete_result.unwrap_or_else(|e| {
                        let giveup = if let Error::MethodFailed(_, code, _) = e {
                            code == 404
                        } else {
                            false
                        };
                        // Allow the user to quit the finalizer loop by setting spec.client.teardown to true
                        if !self.spec.client.teardown.unwrap_or(false) && !giveup {
                            target_new.push(old.clone());
                            conditions.push(ApplicationCondition::write_delete_failed(
                                format!(
                                    "Deleting write.{}.{} {e:?}",
                                    old.group.as_str(),
                                    old.name.as_str()
                                )
                                .as_str(),
                            ));
                        }
                        target_new.push(old.clone());
                        tokio::task::block_in_place(|| {
                            Handle::current().block_on(async {
                                Self::publish_warning(
                                    &recorder,
                                    &obj_ref,
                                    format!("Failed deleting: write.{}.{}", old.group, old.name),
                                    format!("{e:?}"),
                                    String::from("deleting"),
                                )
                                .await
                                .unwrap_or(());
                            })
                        });
                        json!({})
                    });
                }
            }
        } else {
            warn!("Write failures detected ({}), no cleanup processed.", failures);
        }
        // Verify that all writes went OK
        let cnd = conditions.clone();
        if cnd.iter().any(|c| {
            c.condition_type != ConditionsType::InputMissing
                && c.condition_type != ConditionsType::ReadMissing
                && c.condition_type != ConditionsType::WriteAlreadyExist
        }) {
            let msg = "Some writes have failed";
            Self::publish_warning(
                &recorder,
                &obj_ref,
                String::from(msg),
                format!("Found {} error(s) while writing values", conditions.len()),
                String::from("fail"),
            )
            .await?;
            conditions.push(ApplicationCondition::not_ready(msg));
            let new_status = Patch::Apply(json!({
                "apiVersion": "kuberest.solidite.fr/v1",
                "kind": "RestEndPoint",
                "status": RestEndPointStatus { conditions, generation: self.metadata.generation.unwrap_or(1), owned: self.owned(), owned_target: target_new }
            }));
            let ps = PatchParams::apply(RESTPATH_FINALIZER).force();
            let _o = restendpoints
                .patch_status(&name, &ps, &new_status)
                .await
                .map_err(Error::KubeError)?;
            return Ok(Action::requeue(Duration::from_secs(
                self.spec.retry_frequency.unwrap_or(5 * 60),
            )));
        }
        rhai.set_dynamic("write", &values["write"]);
        rhai.set_dynamic("values", &values);

        // Run the post script
        if let Some(script) = self.spec.post.clone() {
            values["post"] = rhai.eval(&script).unwrap_or_else(|e| {
                conditions.push(ApplicationCondition::post_script_failed(&format!("{e:?}")));
                json!({})
            });
            // Validate that post-script went Ok
            let cnd = conditions.clone();
            if cnd.iter().any(|c| {
                c.condition_type != ConditionsType::InputMissing
                    && c.condition_type != ConditionsType::ReadMissing
            }) {
                let msg = "Post-script failed";
                Self::publish_warning(
                    &recorder,
                    &obj_ref,
                    String::from(msg),
                    format!("Found {} error(s) during post-script", conditions.len()),
                    String::from("fail"),
                )
                .await?;
                conditions.push(ApplicationCondition::not_ready(msg));
                let new_status = Patch::Apply(json!({
                    "apiVersion": "kuberest.solidite.fr/v1",
                    "kind": "RestEndPoint",
                    "status": RestEndPointStatus { conditions, generation: self.metadata.generation.unwrap_or(1), owned: self.owned(), owned_target: self.owned_target() }
                }));
                let ps = PatchParams::apply(RESTPATH_FINALIZER).force();
                let _o = restendpoints
                    .patch_status(&name, &ps, &new_status)
                    .await
                    .map_err(Error::KubeError)?;
                return Ok(Action::requeue(Duration::from_secs(
                    self.spec.retry_frequency.unwrap_or(5 * 60),
                )));
            }
        }

        // Finally: handle Outputs
        let mut owned_new: Vec<OwnedObjects> = Vec::new();
        if let Some(outputs) = self.spec.outputs.clone() {
            for output in outputs {
                let my_ns = if use_multi {
                    if let Some(o_ns) = output.metadata.namespace.clone() {
                        if allowed.contains(&o_ns) {
                            o_ns
                        } else {
                            Self::publish_warning(&recorder, &obj_ref, String::from("IgnoredNamespace"), format!("Ignoring namespace from Input '{}' as the operator run in multi-tenant mode",output.metadata.name), String::from("readingOutput")).await?;
                            ns.clone()
                        }
                    } else {
                        ns.clone()
                    }
                } else if let Some(local_ns) = output.clone().metadata.namespace {
                    local_ns
                } else {
                    ns.clone()
                };
                let mut my_values: HashMap<String, String> = HashMap::new();
                for (key, val) in output.clone().data {
                    my_values.insert(
                        template!(key.as_str(), hbs, &values, conditions, recorder, &obj_ref),
                        template!(val.as_str(), hbs, &values, conditions, recorder, &obj_ref),
                    );
                }
                if output.kind == Kind::Secret {
                    let mut secrets = SecretHandler::new(&ctx.client.clone(), &my_ns);
                    if self.owned().clone().into_iter().any(|o| {
                        o.kind == output.kind && o.name == output.metadata.name && o.namespace == my_ns
                    }) {
                        let myself = self
                            .owned()
                            .clone()
                            .into_iter()
                            .find(|o| {
                                o.kind == output.kind
                                    && o.name == output.metadata.name
                                    && o.namespace == my_ns
                            })
                            .unwrap();
                        if secrets.have_uid(&myself.name, &myself.uid).await {
                            if !secrets.have_with_data(&myself.name, &my_values).await {
                                let _ = update!(
                                    secrets, "Secret", output, my_ns, &my_values, conditions, recorder,
                                    &obj_ref
                                );
                            }
                            owned_new.push(myself);
                        } else if secrets.have(&myself.name).await {
                            if !secrets.have_with_data(&myself.name, &my_values).await {
                                let _ = update!(
                                    secrets, "Secret", output, my_ns, &my_values, conditions, recorder,
                                    &obj_ref
                                );
                            }
                            if output.teardown.unwrap_or(true) {
                                conditions.push(ApplicationCondition::output_exist(&format!(
                                    "Secret output '{}.{}' already exist, won't take ownership.",
                                    my_ns, output.metadata.name
                                )));
                            }
                        } else {
                            let own = if output.teardown.unwrap_or(true)
                                && my_ns == self.namespace().unwrap_or(my_ns.clone())
                            {
                                Some(self)
                            } else {
                                None
                            };
                            if let Some(sec) = create!(
                                secrets, "Secret", own, output, my_ns, &my_values, conditions, recorder,
                                &obj_ref
                            ) && output.teardown.unwrap_or(true)
                            {
                                owned_new.push(OwnedObjects::secret(
                                    sec.metadata.name.unwrap().as_str(),
                                    sec.metadata.namespace.unwrap().as_str(),
                                    sec.metadata.uid.unwrap().as_str(),
                                ));
                            }
                        }
                    } else if secrets.have(&output.metadata.name).await {
                        if !secrets.have_with_data(&output.metadata.name, &my_values).await {
                            let _ = update!(
                                secrets, "Secret", output, my_ns, &my_values, conditions, recorder, &obj_ref
                            );
                        }
                        if output.teardown.unwrap_or(true) {
                            conditions.push(ApplicationCondition::output_exist(&format!(
                                "Secret output '{}.{}' already exist, won't take ownership.",
                                my_ns, output.metadata.name
                            )));
                        }
                    } else {
                        let own = if output.teardown.unwrap_or(true)
                            && my_ns == self.namespace().unwrap_or(my_ns.clone())
                        {
                            Some(self)
                        } else {
                            None
                        };
                        if let Some(sec) = create!(
                            secrets,
                            "Secret",
                            own,
                            output.clone(),
                            my_ns,
                            &my_values,
                            conditions,
                            recorder,
                            &obj_ref
                        ) && output.teardown.unwrap_or(true)
                        {
                            owned_new.push(OwnedObjects::secret(
                                sec.metadata.name.unwrap().as_str(),
                                sec.metadata.namespace.unwrap().as_str(),
                                sec.metadata.uid.unwrap().as_str(),
                            ));
                        }
                    }
                } else if output.kind == Kind::ConfigMap {
                    let mut cms = ConfigMapHandler::new(&ctx.client.clone(), &my_ns);
                    if self.owned().clone().into_iter().any(|o| {
                        o.kind == output.kind && o.name == output.metadata.name && o.namespace == my_ns
                    }) {
                        let myself = self
                            .owned()
                            .clone()
                            .into_iter()
                            .find(|o| {
                                o.kind == output.kind
                                    && o.name == output.metadata.name
                                    && o.namespace == my_ns
                            })
                            .unwrap();
                        if cms.have_uid(&myself.name, &myself.uid).await {
                            if !cms.have_with_data(&myself.name, &my_values).await {
                                let _ = update!(
                                    cms,
                                    "ConfigMap",
                                    output,
                                    my_ns,
                                    &my_values,
                                    conditions,
                                    recorder,
                                    &obj_ref
                                );
                            }
                            owned_new.push(myself);
                        } else if cms.have(&myself.name).await {
                            if !cms.have_with_data(&myself.name, &my_values).await {
                                let _ = update!(
                                    cms,
                                    "ConfigMap",
                                    output,
                                    my_ns,
                                    &my_values,
                                    conditions,
                                    recorder,
                                    &obj_ref
                                );
                            }
                            if output.teardown.unwrap_or(true) {
                                conditions.push(ApplicationCondition::output_exist(&format!(
                                    "ConfigMap output '{}.{}' already exist, won't take ownership.",
                                    my_ns, output.metadata.name
                                )));
                            }
                        } else {
                            let own = if output.teardown.unwrap_or(true)
                                && my_ns == self.namespace().unwrap_or(my_ns.clone())
                            {
                                Some(self)
                            } else {
                                None
                            };
                            if let Some(sec) = create!(
                                cms,
                                "ConfigMap",
                                own,
                                output,
                                my_ns,
                                &my_values,
                                conditions,
                                recorder,
                                &obj_ref
                            ) && output.teardown.unwrap_or(true)
                            {
                                owned_new.push(OwnedObjects::configmap(
                                    sec.metadata.name.unwrap().as_str(),
                                    sec.metadata.namespace.unwrap().as_str(),
                                    sec.metadata.uid.unwrap().as_str(),
                                ));
                            }
                        }
                    } else if cms.have(&output.metadata.name).await {
                        if !cms.have_with_data(&output.metadata.name, &my_values).await {
                            let _ = update!(
                                cms,
                                "ConfigMap",
                                output,
                                my_ns,
                                &my_values,
                                conditions,
                                recorder,
                                &obj_ref
                            );
                        }
                        if output.teardown.unwrap_or(true) {
                            conditions.push(ApplicationCondition::output_exist(&format!(
                                "ConfigMap output '{}.{}' already exist, won't take ownership.",
                                my_ns, output.metadata.name
                            )));
                        }
                    } else {
                        let own = if output.teardown.unwrap_or(true)
                            && my_ns == self.namespace().unwrap_or(my_ns.clone())
                        {
                            Some(self)
                        } else {
                            None
                        };
                        if let Some(sec) = create!(
                            cms,
                            "ConfigMap",
                            own,
                            output.clone(),
                            my_ns,
                            &my_values,
                            conditions,
                            recorder,
                            &obj_ref
                        ) && output.teardown.unwrap_or(true)
                        {
                            owned_new.push(OwnedObjects::configmap(
                                sec.metadata.name.unwrap().as_str(),
                                sec.metadata.namespace.unwrap().as_str(),
                                sec.metadata.uid.unwrap().as_str(),
                            ));
                        }
                    }
                }
            }
        }
        // Handle every owned object that is not in the new list
        for obj in self.clone().owned() {
            if !owned_new
                .clone()
                .into_iter()
                .any(|n| n.kind == obj.kind && n.namespace == obj.namespace && n.name == obj.name)
            {
                if obj.kind == Kind::Secret {
                    let mut secrets = SecretHandler::new(&ctx.client.clone(), &obj.namespace);
                    if secrets.have_uid(&obj.name, &obj.uid).await {
                        secrets.delete(obj.name.as_str()).await.unwrap_or_else(|e| {
                            conditions.push(ApplicationCondition::output_delete_failed(&format!(
                                "Failed deleting: {}.{}: {:?}",
                                obj.namespace, obj.name, e
                            )));
                            owned_new.push(obj.clone());
                        })
                    }
                } else if obj.kind == Kind::ConfigMap {
                    let mut cms = ConfigMapHandler::new(&ctx.client.clone(), &obj.namespace);
                    if cms.have_uid(&obj.name, &obj.uid).await {
                        cms.delete(obj.name.as_str()).await.unwrap_or_else(|e| {
                            conditions.push(ApplicationCondition::output_delete_failed(&format!(
                                "Failed deleting: {}.{}: {:?}",
                                obj.namespace, obj.name, e
                            )));
                            owned_new.push(obj.clone());
                        })
                    }
                }
            }
        }

        // Verify that everything went fine and update the status accordingly
        if conditions.iter().any(|c| {
            c.condition_type != ConditionsType::InputMissing
                && c.condition_type != ConditionsType::ReadMissing
                && c.condition_type != ConditionsType::WriteAlreadyExist
                && c.condition_type != ConditionsType::OutputAlreadyExist
        }) {
            let msg = "Some output have failed";
            Self::publish_warning(
                &recorder,
                &obj_ref,
                String::from(msg),
                format!("Found {} error(s) while creating outputs", conditions.len()),
                String::from("fail"),
            )
            .await?;
            conditions.push(ApplicationCondition::not_ready(msg));
            let new_status = Patch::Apply(json!({
                "apiVersion": "kuberest.solidite.fr/v1",
                "kind": "RestEndPoint",
                "status": RestEndPointStatus { conditions, generation: self.metadata.generation.unwrap_or(1), owned: owned_new, owned_target: target_new }
            }));
            let ps = PatchParams::apply(RESTPATH_FINALIZER).force();
            let _o = restendpoints
                .patch_status(&name, &ps, &new_status)
                .await
                .map_err(Error::KubeError)?;
            Ok(Action::requeue(Duration::from_secs(
                self.spec.retry_frequency.unwrap_or(5 * 60),
            )))
        } else {
            let msg = "All done";
            conditions.push(ApplicationCondition::is_ready(msg));
            let new_status = Patch::Apply(json!({
                "apiVersion": "kuberest.solidite.fr/v1",
                "kind": "RestEndPoint",
                "status": RestEndPointStatus { conditions, generation: self.metadata.generation.unwrap_or(1), owned: owned_new, owned_target: target_new }
            }));
            let ps = PatchParams::apply(RESTPATH_FINALIZER).force();
            let _o = restendpoints
                .patch_status(&name, &ps, &new_status)
                .await
                .map_err(Error::KubeError)?;
            let wait_duration = self.spec.check_frequency.unwrap_or(60 * 60);
            if wait_duration > 0 {
                Ok(Action::requeue(Duration::from_secs(wait_duration)))
            } else {
                Ok(Action::await_change())
            }
        }
    }

    // Finalizer cleanup (the object was deleted, ensure nothing is orphaned)
    async fn cleanup(&self, ctx: Arc<Context>) -> Result<Action> {
        let client = ctx.client.clone();
        ctx.diagnostics.write().await.last_event = Utc::now();
        let reporter = ctx.diagnostics.read().await.reporter.clone();
        let recorder = Recorder::new(client.clone(), reporter);
        let obj_ref = self.object_ref(&());
        let ns = self.namespace().unwrap();
        let name = self.name_any();
        let restendpoints: Api<RestEndPoint> = Api::namespaced(client.clone(), &ns);
        let mut conditions: Vec<ApplicationCondition> = Vec::new();
        let mut values = serde_json::json!({"input":{},"pre":{}});
        let mut hbs = HandleBars::new();
        if let Some(templates) = self.spec.templates.clone() {
            for item in templates {
                hbs.register_template(&item.name, &item.template)
                    .unwrap_or_else(|e| {
                        conditions.push(ApplicationCondition::template_failed(&format!(
                            "Registering template.{} raised {e:?}",
                            item.name
                        )));
                    });
            }
        }
        let use_multi = std::env::var("MULTI_TENANT")
            .unwrap_or_else(|_| "true".to_string())
            .to_lowercase()
            == *"true";
        let allowed = if use_multi && (self.spec.inputs.is_some() || self.spec.outputs.is_some()) {
            self.get_tenant_namespaces(client.clone()).await?
        } else {
            Vec::new()
        };
        let mut do_prepare_client = true;
        if self.status.is_none() {
            // Nothing to do, since there's nothing to delete
            return Ok(Action::await_change());
        } else if self.spec.teardown.is_none() {
            // no teardown script, only prepare client if there are some write to delete
            let status = self.status.clone().unwrap();
            do_prepare_client = !status.owned_target.is_empty();
        }
        if !do_prepare_client {
            tracing::info!("Skipping to prepare the client");
        }
        let mut rhai = Script::new();
        rhai.ctx.set_or_push("hbs", hbs.clone());
        // Read the inputs first
        if do_prepare_client {
            if let Some(inputs) = self.spec.clone().inputs {
                for input in inputs {
                    if let Some(secret) = input.secret_ref {
                        let my_ns = if use_multi {
                            if let Some(o_ns) = secret.namespace.clone() {
                                if allowed.contains(&o_ns) {
                                    o_ns
                                } else {
                                    Self::publish_warning(&recorder, &obj_ref, String::from("IgnoredNamespace"), format!("Ignoring namespace from Input '{}' as the operator run in multi-tenant mode",input.name), String::from("readingInput")).await?;
                                    ns.clone()
                                }
                            } else {
                                ns.clone()
                            }
                        } else if let Some(local_ns) = secret.namespace {
                            local_ns
                        } else {
                            ns.clone()
                        };
                        let mut secrets = SecretHandler::new(&ctx.client.clone(), &my_ns);
                        if secrets.have(&secret.name).await {
                            let my_secret = secrets.get(&secret.name).await.unwrap();
                            values["input"][input.name] = serde_json::json!({
                                "metadata": my_secret.metadata,
                                "data": my_secret.data
                            });
                        } else if secret.optional.unwrap_or(false) {
                            Self::publish(
                                &recorder,
                                &obj_ref,
                                String::from("IgnoredInput"),
                                format!("Ignoring not found secret for Input '{}'", input.name),
                                String::from("readingInput"),
                            )
                            .await?;
                            conditions.push(ApplicationCondition::input_missing(&format!(
                                "Input '{}' Secret {}.{} not found",
                                input.name, my_ns, secret.name
                            )));
                            values["input"][input.name] = serde_json::json!({});
                        } else {
                            Self::publish(
                                &recorder,
                                &obj_ref,
                                String::from("MissingSecret"),
                                format!("Secret '{}' not found for Input '{}'", secret.name, input.name),
                                String::from("readingInput"),
                            )
                            .await?;
                            conditions.push(ApplicationCondition::input_failed(&format!(
                                "Input '{}' Secret {}.{} not found",
                                input.name, my_ns, secret.name
                            )));
                        }
                    } else if let Some(cfgmap) = input.config_map_ref {
                        let my_ns = if use_multi {
                            if let Some(o_ns) = cfgmap.namespace.clone() {
                                if allowed.contains(&o_ns) {
                                    o_ns
                                } else {
                                    Self::publish_warning(&recorder, &obj_ref, String::from("IgnoredNamespace"), format!("Ignoring namespace from Input '{}' as the operator run in multi-tenant mode",input.name), String::from("readingInput")).await?;
                                    ns.clone()
                                }
                            } else {
                                ns.clone()
                            }
                        } else if let Some(local_ns) = cfgmap.namespace {
                            local_ns
                        } else {
                            ns.clone()
                        };
                        let mut maps = ConfigMapHandler::new(&ctx.client.clone(), &my_ns);
                        if maps.have(&cfgmap.name).await {
                            let my_cfg = maps.get(&cfgmap.name).await.unwrap();
                            values["input"][input.name] = serde_json::json!({
                                "metadata": my_cfg.metadata,
                                "data": my_cfg.data,
                                "binaryData": my_cfg.binary_data
                            });
                        } else if cfgmap.optional.unwrap_or(false) {
                            Self::publish(
                                &recorder,
                                &obj_ref,
                                String::from("IgnoredInput"),
                                format!("Ignoring not found ConfigMap for Input '{}'", input.name),
                                String::from("readingInput"),
                            )
                            .await?;
                            conditions.push(ApplicationCondition::input_missing(&format!(
                                "Input '{}' ConfigMap {}.{} not found",
                                input.name, my_ns, cfgmap.name
                            )));
                            values["input"][input.name] = serde_json::json!({});
                        } else {
                            Self::publish(
                                &recorder,
                                &obj_ref,
                                String::from("MissingConfigMap"),
                                format!("ConfigMap '{}' not found for Input '{}'", cfgmap.name, input.name),
                                String::from("readingInput"),
                            )
                            .await?;
                            conditions.push(ApplicationCondition::input_failed(&format!(
                                "Input '{}' ConfigMap {}.{} not found",
                                input.name, my_ns, cfgmap.name
                            )));
                        }
                    } else if let Some(render) = input.handle_bars_render {
                        values["input"][input.name] = json!(template!(
                            render.as_str(),
                            hbs,
                            &values,
                            conditions,
                            recorder,
                            &obj_ref
                        ));
                    } else if let Some(password_def) = input.password_generator {
                        values["input"][input.name] = json!(Passwords::new().generate(
                            password_def.length.unwrap_or(32),
                            password_def.weight_alphas.unwrap_or(60),
                            password_def.weight_numbers.unwrap_or(20),
                            password_def.weight_symbols.unwrap_or(20)
                        ));
                    } else {
                        Self::publish_warning(
                            &recorder,
                            &obj_ref,
                            String::from("EmptyInput"),
                            format!("Input '{}' have no source", input.name),
                            String::from("fail"),
                        )
                        .await?;
                        conditions.push(ApplicationCondition::input_failed(&format!(
                            "Input '{}' have no source",
                            input.name
                        )));
                        conditions.push(ApplicationCondition::not_ready(&format!(
                            "Input '{}' have no source",
                            input.name
                        )));
                        let new_status = Patch::Apply(json!({
                            "apiVersion": "kuberest.solidite.fr/v1",
                            "kind": "RestEndPoint",
                            "status": RestEndPointStatus { conditions, generation: self.metadata.generation.unwrap_or(1), owned: self.owned(), owned_target: self.owned_target() }
                        }));
                        let ps = PatchParams::apply(RESTPATH_FINALIZER).force();
                        let _o = restendpoints
                            .patch_status(&name, &ps, &new_status)
                            .await
                            .map_err(Error::KubeError)?;
                        return Err(Error::IllegalRestEndPoint);
                    }
                }
            }
            rhai.set_dynamic("input", &values["input"]);
            rhai.set_dynamic("values", &values);

            // Run the init script
            if let Some(script) = self.spec.init.clone() {
                let cnd = conditions.clone();
                values["init"] = rhai.eval(&script).unwrap_or_else(|e| {
                    conditions.push(ApplicationCondition::init_script_failed(&format!("{e:?}")));
                    json!({})
                });
                // Validate that init-script went Ok
                if cnd
                    .iter()
                    .any(|c| c.condition_type != ConditionsType::InputMissing)
                {
                    let msg = "Init-script failed";
                    Self::publish_warning(
                        &recorder,
                        &obj_ref,
                        String::from(msg),
                        format!("Found {} error(s) running the init-script", conditions.len()),
                        String::from("fail"),
                    )
                    .await?;
                    conditions.push(ApplicationCondition::not_ready(msg));
                    let new_status = Patch::Apply(json!({
                        "apiVersion": "kuberest.solidite.fr/v1",
                        "kind": "RestEndPoint",
                        "status": RestEndPointStatus { conditions, generation: self.metadata.generation.unwrap_or(1), owned: self.owned(), owned_target: self.owned_target() }
                    }));
                    let ps = PatchParams::apply(RESTPATH_FINALIZER).force();
                    let _o = restendpoints
                        .patch_status(&name, &ps, &new_status)
                        .await
                        .map_err(Error::KubeError)?;
                    return Ok(Action::requeue(Duration::from_secs(
                        self.spec.retry_frequency.unwrap_or(5 * 60),
                    )));
                }
            }
            rhai.set_dynamic("init", &values["init"]);
            rhai.set_dynamic("values", &values);
        }

        // Setup the httpClient
        let mut rest = RestClient::new(&template!(
            self.spec.client.baseurl.clone().as_str(),
            hbs,
            &values,
            conditions,
            recorder,
            &obj_ref
        ));
        if do_prepare_client {
            if let Some(headers) = self.spec.client.headers.clone() {
                for (key, value) in headers {
                    rest.add_header(
                        &template!(key.as_str(), hbs, &values, conditions, recorder, &obj_ref),
                        &template!(value.as_str(), hbs, &values, conditions, recorder, &obj_ref),
                    );
                }
            }
            rest.add_header_json();
            if let Some(ca) = self.spec.client.server_ca.clone() {
                rest.set_server_ca(&template!(
                    &ca.as_str(),
                    hbs,
                    &values,
                    conditions,
                    recorder,
                    &obj_ref
                ));
            }
            if self.spec.client.client_cert.is_some() && self.spec.client.client_key.is_some() {
                rest.set_mtls(
                    &template!(
                        &self.spec.client.client_cert.clone().unwrap().as_str(),
                        hbs,
                        &values,
                        conditions,
                        recorder,
                        &obj_ref
                    ),
                    &template!(
                        &self.spec.client.client_key.clone().unwrap().as_str(),
                        hbs,
                        &values,
                        conditions,
                        recorder,
                        &obj_ref
                    ),
                );
            }
            rhai.ctx.set_or_push("client", rest.clone());
        }

        let mut owned_new: Vec<OwnedObjects> = Vec::new();
        let mut target_new: Vec<OwnedRestPoint> = Vec::new();

        // Start the teardown script
        if let Some(script) = self.spec.teardown.clone() {
            let cnd = conditions.clone();
            values["pre"] = rhai.eval(&script).unwrap_or_else(|e| {
                conditions.push(ApplicationCondition::post_script_failed(&format!("{e:?}")));
                json!({})
            });
            values["teardown"] = values["pre"].clone();
            // Validate that teardown went Ok
            if cnd
                .iter()
                .any(|c| c.condition_type != ConditionsType::InputMissing)
            {
                let msg = "Teardown failed";
                Self::publish_warning(
                    &recorder,
                    &obj_ref,
                    String::from(msg),
                    format!("Found {} error(s) during teardown", conditions.len()),
                    String::from("fail"),
                )
                .await?;
                conditions.push(ApplicationCondition::not_ready(msg));
                let new_status = Patch::Apply(json!({
                    "apiVersion": "kuberest.solidite.fr/v1",
                    "kind": "RestEndPoint",
                    "status": RestEndPointStatus { conditions, generation: self.metadata.generation.unwrap_or(1), owned: self.owned(), owned_target: self.owned_target() }
                }));
                let ps = PatchParams::apply(RESTPATH_FINALIZER).force();
                let _o = restendpoints
                    .patch_status(&name, &ps, &new_status)
                    .await
                    .map_err(Error::KubeError)?;
                return Ok(Action::requeue(Duration::from_secs(
                    self.spec.retry_frequency.unwrap_or(5 * 60),
                )));
            }
        }

        // Delete writes
        if let Some(status) = self.status.clone() {
            for obj in status.owned_target {
                if obj.teardown && !obj.key.is_empty() {
                    let delete_result = if obj.children_no_sub_key.unwrap_or(false) {
                        let del_key_name = obj.key_name.clone().unwrap_or("id".to_string());
                        rest.obj_delete_with_body(
                            DeleteMethod::Delete,
                            &obj.path,
                            &json!({del_key_name: obj.key}),
                        )
                    } else {
                        rest.obj_delete(DeleteMethod::Delete, &obj.path, &obj.key)
                    };
                    delete_result.unwrap_or_else(|e| {
                        let giveup = if let Error::MethodFailed(_, code, _) = e {
                            code == 404
                        } else {
                            false
                        };
                        // Allow the user to quit the finalizer loop by setting spec.client.teardown to true
                        if !self.spec.client.teardown.unwrap_or(false) && !giveup {
                            target_new.push(obj.clone());
                            conditions.push(ApplicationCondition::write_delete_failed(
                                format!(
                                    "Deleting write.{}.{} {e:?}",
                                    obj.group.as_str(),
                                    obj.name.as_str()
                                )
                                .as_str(),
                            ));
                        }
                        tokio::task::block_in_place(|| {
                            Handle::current().block_on(async {
                                Self::publish_warning(
                                    &recorder,
                                    &obj_ref,
                                    format!("Failed deleting: write.{}.{}", obj.group, obj.name),
                                    format!("{e:?}"),
                                    String::from("deleting"),
                                )
                                .await
                                .unwrap_or(());
                            })
                        });
                        json!({})
                    });
                }
            }
        }

        // Delete owned objects
        if let Some(status) = self.status.clone() {
            for obj in status.owned {
                if obj.kind == Kind::Secret {
                    let mut secrets = SecretHandler::new(&ctx.client.clone(), &obj.namespace);
                    if secrets.have_uid(&obj.name, &obj.uid).await {
                        secrets.delete(obj.name.as_str()).await.unwrap_or_else(|e| {
                            conditions.push(ApplicationCondition::output_delete_failed(&format!(
                                "Failed deleting: {}.{}: {:?}",
                                obj.namespace, obj.name, e
                            )));
                            owned_new.push(obj.clone());
                        })
                    }
                } else if obj.kind == Kind::ConfigMap {
                    let mut secrets = ConfigMapHandler::new(&ctx.client.clone(), &obj.namespace);
                    if secrets.have_uid(&obj.name, &obj.uid).await {
                        secrets.delete(obj.name.as_str()).await.unwrap_or_else(|e| {
                            conditions.push(ApplicationCondition::output_delete_failed(&format!(
                                "Failed deleting: {}.{}: {:?}",
                                obj.namespace, obj.name, e
                            )));
                            owned_new.push(obj.clone());
                        })
                    }
                }
            }
        }
        if conditions.iter().any(|c| {
            c.condition_type != ConditionsType::InputMissing
                && c.condition_type != ConditionsType::ReadMissing
                && c.condition_type != ConditionsType::WriteAlreadyExist
                && c.condition_type != ConditionsType::OutputAlreadyExist
        }) || !owned_new.is_empty()
            || !target_new.is_empty()
        {
            let msg = "Some teardown failed";
            Self::publish_warning(
                &recorder,
                &obj_ref,
                String::from(msg),
                format!("Found {} error(s) during teardown", conditions.len()),
                String::from("fail"),
            )
            .await?;
            // Wait 30s before reporting the failure, because the controller keeps trying and it might hammer the api-server and the api-endpoint targeted otherwise. Beside the events generated already informed the user of the issue
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
                })
            });
            conditions.push(ApplicationCondition::not_ready(msg));
            let new_status = Patch::Apply(json!({
                "apiVersion": "kuberest.solidite.fr/v1",
                "kind": "RestEndPoint",
                "status": RestEndPointStatus { conditions, generation: self.metadata.generation.unwrap_or(1), owned: owned_new, owned_target: target_new }
            }));
            let ps = PatchParams::apply(RESTPATH_FINALIZER).force();
            let _o = restendpoints
                .patch_status(&name, &ps, &new_status)
                .await
                .map_err(Error::KubeError)?;
            Err(Error::TeardownIncomplete)
        } else {
            Ok(Action::await_change())
        }
    }
}

/// Diagnostics to be exposed by the web server
#[derive(Clone, Serialize)]
pub struct Diagnostics {
    #[serde(deserialize_with = "from_ts")]
    pub last_event: DateTime<Utc>,
    #[serde(skip)]
    pub reporter: Reporter,
}
impl Default for Diagnostics {
    fn default() -> Self {
        Self {
            last_event: Utc::now(),
            reporter: "restendpoint-controller".into(),
        }
    }
}
impl Diagnostics {
    fn recorder(&self, client: Client) -> Recorder {
        Recorder::new(client, self.reporter.clone())
    }
}

/// State shared between the controller and the web server
#[derive(Clone, Default)]
pub struct State {
    /// Diagnostics populated by the reconciler
    diagnostics: Arc<RwLock<Diagnostics>>,
    /// Metrics registry
    registry: prometheus::Registry,
}

/// State wrapper around the controller outputs for the web server
impl State {
    /// Metrics getter
    pub fn metrics(&self) -> Vec<prometheus::proto::MetricFamily> {
        self.registry.gather()
    }

    /// State getter
    pub async fn diagnostics(&self) -> Diagnostics {
        self.diagnostics.read().await.clone()
    }

    // Create a Controller Context that can update State
    pub fn to_context(&self, client: Client) -> Arc<Context> {
        Arc::new(Context {
            client,
            metrics: Metrics::default().register(&self.registry).unwrap(),
            diagnostics: self.diagnostics.clone(),
        })
    }
}

/// Initialize the controller and shared state (given the crd is installed)
pub async fn run(state: State) {
    let client: Client = Client::try_default().await.expect("failed to create kube Client");
    let restendpoints = Api::<RestEndPoint>::all(client.clone());
    if let Err(e) = restendpoints.list(&ListParams::default().limit(1)).await {
        error!("CRD is not queryable; {e:?}. Is the CRD installed?");
        info!("Installation: cargo run --bin crdgen | kubectl apply -f -");
        std::process::exit(1);
    }
    Controller::new(restendpoints, Config::default().any_semantic())
        .shutdown_on_signal()
        .run(reconcile, error_policy, state.to_context(client))
        .filter_map(|x| async move { std::result::Result::ok(x) })
        .for_each(|_| futures::future::ready(()))
        .await;
}

// Mock tests relying on fixtures.rs and its primitive apiserver mocks
#[cfg(test)]
mod test {
    use super::{Context, RestEndPoint, /* error_policy, */ reconcile};
    use crate::fixtures::{Scenario, timeout_after_1s};
    use std::sync::Arc;

    #[tokio::test]
    async fn restendpoint_without_finalizer_gets_a_finalizer() {
        let (testctx, fakeserver, _) = Context::test();
        let restendpoint = RestEndPoint::test();
        let mocksrv = fakeserver.run(Scenario::FinalizerCreation(restendpoint.clone()));
        reconcile(Arc::new(restendpoint), testctx)
            .await
            .expect("reconciler");
        timeout_after_1s(mocksrv).await;
    }

    #[tokio::test]
    async fn finalized_restendpoint_causes_status_patch() {
        let (testctx, fakeserver, _) = Context::test();
        let restendpoint = RestEndPoint::test().finalized();
        let mocksrv = fakeserver.run(Scenario::StatusPatch(restendpoint.clone()));
        reconcile(Arc::new(restendpoint), testctx)
            .await
            .expect("reconciler");
        timeout_after_1s(mocksrv).await;
    }

    /* TODO: include more Unit-tests
        #[tokio::test]
        async fn finalized_restendpoint_with_hide_causes_event_and_hide_patch() {
            let (testctx, fakeserver, _) = Context::test();
            let restendpoint = RestEndPoint::test().finalized().needs_hide();
            let scenario = Scenario::EventPublishThenStatusPatch("HideRequested".into(), restendpoint.clone());
            let mocksrv = fakeserver.run(scenario);
            reconcile(Arc::new(restendpoint), testctx).await.expect("reconciler");
            timeout_after_1s(mocksrv).await;
        }
    #[tokio::test]
    async fn finalized_restendpoint_with_delete_timestamp_causes_delete() {
        let (testctx, fakeserver, _) = Context::test();
        let restendpoint = RestEndPoint::test().finalized().needs_delete();
        let mocksrv = fakeserver.run(Scenario::Cleanup("DeleteRequested".into(), restendpoint.clone()));
        reconcile(Arc::new(restendpoint), testctx)
            .await
            .expect("reconciler");
        timeout_after_1s(mocksrv).await;
    }
        #[tokio::test]
        async fn illegal_restendpoint_reconcile_errors_which_bumps_failure_metric() {
            let (testctx, fakeserver, _registry) = Context::test();
            let restendpoint = Arc::new(RestEndPoint::illegal().finalized());
            let mocksrv = fakeserver.run(Scenario::RadioSilence);
            let res = reconcile(restendpoint.clone(), testctx.clone()).await;
            timeout_after_1s(mocksrv).await;
            assert!(res.is_err(), "apply reconciler fails on illegal restendpoint");
            let err = res.unwrap_err();
            assert!(err.to_string().contains("IllegalRestEndPoint"));
            // calling error policy with the reconciler error should cause the correct metric to be set
            error_policy(restendpoint.clone(), &err, testctx.clone());
            //dbg!("actual metrics: {}", registry.gather());
            let failures = testctx
                .metrics
                .failures
                .with_label_values(&["illegal", "finalizererror(applyfailed(illegalrestendpointument))"])
                .get();
            assert_eq!(failures, 1);
        }
    */
    /*
        // Integration test without mocks
        use kube::api::{Api, ListParams, Patch, PatchParams};
        #[tokio::test]
        #[ignore = "uses k8s current-context"]
        async fn integration_reconcile_should_set_status_and_send_event() {
            let client = kube::Client::try_default().await.unwrap();
            let ctx = super::State::default().to_context(client.clone());

            // create a test restendpoint
            let restendpoint = RestEndPoint::test().finalized().needs_hide();
            let restendpoints: Api<RestEndPoint> = Api::namespaced(client.clone(), "default");
            let ssapply = PatchParams::apply("ctrltest");
            let patch = Patch::Apply(restendpoint.clone());
            restendpoints.patch("test", &ssapply, &patch).await.unwrap();

            // reconcile it (as if it was just applied to the cluster like this)
            reconcile(Arc::new(restendpoint), ctx).await.unwrap();

            // verify side-effects happened
            let output = restendpoints.get_status("test").await.unwrap();
            assert!(output.status.is_some());
            // verify hide event was found
            let events: Api<k8s_openapi::api::core::v1::Event> = Api::all(client.clone());
            let opts = ListParams::default().fields("involvedObject.kind=RestEndPoint,involvedObject.name=test");
            let event = events
                .list(&opts)
                .await
                .unwrap()
                .into_iter()
                .filter(|e| e.reason.as_deref() == Some("HideRequested"))
                .last()
                .unwrap();
            dbg!("got ev: {:?}", &event);
            assert_eq!(event.action.as_deref(), Some("Hiding"));
        }
    */
}
