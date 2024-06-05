use std::collections::HashMap;
use crate::{template, update, create, k8shandlers::{SecretHandler,ConfigMapHandler}, handlebarshandler::HandleBars, httphandler::{RestClient,ReadMethod,CreateMethod,UpdateMethod,DeleteMethod}, telemetry, Error, Metrics, Result};
use chrono::{DateTime, Utc};
use futures::StreamExt;
use chrono;
use kube::{
    api::{Api, ListParams, Patch, PatchParams, ResourceExt}, client::Client, runtime::{
        controller::{Action, Controller},
        events::{Event, EventType, Recorder, Reporter},
        finalizer::{finalizer, Event as Finalizer},
        watcher::Config,
    }, CustomResource, Resource
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use tokio::{sync::RwLock, time::Duration, runtime::Handle};
use tracing::*;

pub static RESTPATH_FINALIZER: &str = "restpaths.kuberest.solidite.fr";

/// ConfigMapRef describe a data input for handlebars templates from a ConfigMap
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema)]
pub struct ConfigMapRef {
    /// Name of the ConfigMap
    pub name: String,
    /// Namespace of the ConfigMap, only used if the cross-namespace option is enabled (default: current object namespace)
    pub namespace: Option<String>,
    /// Is the ConfigMap requiered for processing ? (default: false)
    pub optional: Option<bool>,
}

/// SecretRef describe a data input for handlebars templates from a Secret
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema)]
pub struct SecretRef {
    /// Name of the Secret
    pub name: String,
    /// Namespace of the Secret, only used if the cross-namespace option is enabled (default: current object namespace)
    pub namespace: Option<String>,
    /// Is the Secret optional for processing ? (default: false)
    pub optional: Option<bool>
}

// TODO: random data as input (for secret generation)

/// inputItem describe a data input for handlebars templates
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct InputItem {
    /// name of the input (used for handlebars templates)
    pub name: String,
    /// The ConfigMap to select from
    pub config_map_ref: Option<ConfigMapRef>,
    /// The Secret to select from
    pub secret_ref: Option<SecretRef>,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct WebClient {
    /// The baseurl the client will use. All path will use this as a prefix
    pub baseurl: String,
    /// Headers to use on each requests to the endpoint
    pub headers: Option<HashMap<String,String>>,
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
}
impl Default for WebClient {
    fn default() -> Self { WebClient {
        baseurl: "http://localhost:8080".to_string(),
        headers: None,
        key_name: Some("id".to_string()),
        create_method: Some(CreateMethod::Post),
        read_method: Some(ReadMethod::Get),
        update_method: Some(UpdateMethod::Put),
        delete_method: Some(DeleteMethod::Delete),
        teardown: Some(true)
    } }
}

/// readGroupItem describe an object to read with the client
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema)]
pub struct ReadGroupItem {
    /// name of the item (used for handlebars templates)
    pub name: String,
    /// configuration of this object
    pub key: String
}
/// ReadGroup describe a rest endpoint within the client sub-paths,
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema)]
pub struct ReadGroup {
    /// name of the write (used for handlebars templates)
    pub name: String,
    /// path appended to the client's baseurl for this group of objects
    pub path: String,
    /// Method to use when reading an object (default: Post)
    pub read_method: Option<ReadMethod>,
    /// The list of object mapping
    pub items: Vec<ReadGroupItem>
}

/// writeGroupItem describe an object to maintain within
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema)]
pub struct WriteGroupItem {
    /// name of the item (used for handlebars templates: write.<group>.<name>)
    pub name: String,
    /// configuration of this object
    pub inputs: serde_json::Map<String, serde_json::Value>,
    /// Delete the Object on RestEndPoint deletion (default: true, inability to do so will block RestEndPoint)
    teardown: Option<bool>
}
/// writeGroup describe a rest endpoint within the client sub-paths,
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema)]
pub struct WriteGroup {
    /// name of the write (used for handlebars templates: write.<name>)
    pub name: String,
    /// path appended to the client's baseurl for this group of objects
    pub path: String,
    /// keyName: the key of the object (default: id)
    pub key_name: Option<String>,
    /// Method to use when creating an object (default: Get)
    pub create_method: Option<CreateMethod>,
    /// Method to use when reading an object (default: Post)
    pub read_method: Option<ReadMethod>,
    /// Method to use when updating an object (default: Patch)
    pub update_method: Option<UpdateMethod>,
    /// Method to use when deleting an object (default: Delete)
    pub delete_method: Option<DeleteMethod>,
    /// The list of object mapping
    pub items: Vec<WriteGroupItem>,
    /// Delete the Objects on RestEndPoint deletion (default: true, inability to do so will block RestEndPoint)
    teardown: Option<bool>
}

/// metadata describe a rest endpoint within the client sub-paths
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema)]
pub struct Metadata {
    /// name of the created object
    pub name: String,
    /// namespace of the created object
    pub namespace: Option<String>,
    /// labels of the objects
    pub labels: Option<HashMap<String,String>>,
    /// annotations of the objects
    pub annotations: Option<HashMap<String,String>>
}
impl Default for Metadata {
    fn default() -> Self { Metadata {
        name: "default".to_string(),
        namespace: None,
        labels: None,
        annotations: None
    } }
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
    data: HashMap<String,String>,
    /// Delete the Secret on RestEndPoint deletion (default: true)
    teardown: Option<bool>
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema, Default)]
pub enum ConditionsType {
    #[default]
    Ready,
    InputMissing,
    InputFailed,
    TemplateFailed,
    ReadFailed,
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
    pub status: ConditionsStatus
}
impl ApplicationCondition {
    #[must_use] pub fn new(message: &str, status:ConditionsStatus, condition_type:ConditionsType) -> ApplicationCondition {
        ApplicationCondition {
            last_transition_time: Some(chrono::offset::Utc::now()),
            status,
            condition_type,
            message: message.to_string()
        }
    }
    pub fn input_missing(message: &str) -> ApplicationCondition { ApplicationCondition::new(message,ConditionsStatus::True,ConditionsType::InputMissing) }
    pub fn output_exist(message: &str) -> ApplicationCondition { ApplicationCondition::new(message,ConditionsStatus::True,ConditionsType::OutputAlreadyExist) }
    pub fn write_exist(message: &str) -> ApplicationCondition { ApplicationCondition::new(message,ConditionsStatus::True,ConditionsType::WriteAlreadyExist) }
    pub fn input_failed(message: &str) -> ApplicationCondition { ApplicationCondition::new(message,ConditionsStatus::True,ConditionsType::InputFailed) }
    pub fn template_failed(message: &str) -> ApplicationCondition { ApplicationCondition::new(message,ConditionsStatus::True,ConditionsType::TemplateFailed) }
    pub fn read_failed(message: &str) -> ApplicationCondition { ApplicationCondition::new(message,ConditionsStatus::True,ConditionsType::ReadFailed) }
    pub fn write_failed(message: &str) -> ApplicationCondition { ApplicationCondition::new(message,ConditionsStatus::True,ConditionsType::WriteFailed) }
    pub fn write_delete_failed(message: &str) -> ApplicationCondition { ApplicationCondition::new(message,ConditionsStatus::True,ConditionsType::WriteDeleteFailed) }
    pub fn output_failed(message: &str) -> ApplicationCondition { ApplicationCondition::new(message,ConditionsStatus::True,ConditionsType::OutputFailed) }
    pub fn output_delete_failed(message: &str) -> ApplicationCondition { ApplicationCondition::new(message,ConditionsStatus::True,ConditionsType::OutputDeleteFailed) }
    pub fn is_ready(message: &str) -> ApplicationCondition { ApplicationCondition::new(message,ConditionsStatus::True,ConditionsType::Ready) }
    pub fn not_ready(message: &str) -> ApplicationCondition { ApplicationCondition::new(message,ConditionsStatus::False,ConditionsType::Ready) }
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
    pub uid: String
}
impl OwnedObjects {
    #[must_use] pub fn new(kind: Kind, name: &str, namespace: &str, uid:&str) -> OwnedObjects {
        OwnedObjects {
            kind,
            name: name.to_string(),
            namespace: namespace.to_string(),
            uid: uid.to_string()
        }
    }
    pub fn secret(name: &str, namespace: &str, uid:&str) -> OwnedObjects { OwnedObjects::new(Kind::Secret, name, namespace, uid) }
    pub fn configmap(name: &str, namespace: &str, uid:&str) -> OwnedObjects { OwnedObjects::new(Kind::ConfigMap, name, namespace, uid) }
}

/// List all owned rest objects
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct OwnedRestPoint {
    /// Object URL that will receive a delete on teardown
    pub delete_url: String,
    /// Object writeGroup
    pub group: String,
    /// Object name within its writeGroup
    pub name: String
}
impl OwnedRestPoint {
    #[must_use] pub fn new(delete_url: &str, group: &str, name:&str) -> OwnedRestPoint {
        OwnedRestPoint {
            delete_url: delete_url.to_string(),
            group: group.to_string(),
            name: name.to_string()
        }
    }
}

/// Describe the specification of a RestEndPoint
#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[cfg_attr(test, derive(Default))]
#[kube(kind = "RestEndPoint", group = "kuberest.solidite.fr", version = "v1", namespaced, status = "RestEndPointStatus", shortname = "rep")]
#[serde(rename_all = "camelCase")]
pub struct RestEndPointSpec {
    /// List input source for Handlebars templates
    pub inputs: Option<Vec<InputItem>>,
    /// Define the how the client should connect to the API endpoint(s)
    pub client: WebClient,
    /// Allow to read some pre-existing objects
    pub reads: Option<Vec<ReadGroup>>,
    /// Sub-paths to the client. Allow to describe the objects to create on the end-point
    pub writes: Option<Vec<WriteGroup>>,
    /// Objects (Secret or ConfigMap) to create at the end of the process
    pub outputs: Option<Vec<OutputItem>>,
    /// checkFrequency define the pooling interval (in seconds, default: 300)
    pub check_frequency: Option<u64>,
}
/// The status object of `RestEndPoint`
#[derive(Deserialize, Serialize, Clone, Default, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RestEndPointStatus {
    pub conditions: Vec<ApplicationCondition>,
    pub owned: Vec<OwnedObjects>,
    pub owned_target: Vec<OwnedRestPoint>
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
    Span::current().record("trace_id", &field::display(&trace_id));
    let _timer = ctx.metrics.count_and_measure();
    ctx.diagnostics.write().await.last_event = Utc::now();
    let ns = rest_path.namespace().unwrap();
    let paths: Api<RestEndPoint> = Api::namespaced(ctx.client.clone(), &ns);

    debug!("Reconciling RestEndPoint \"{}\" in {}", rest_path.name_any(), ns);
    finalizer(&paths, RESTPATH_FINALIZER, rest_path, |event| async {
        match event {
            Finalizer::Apply(rest_path) => rest_path.reconcile(ctx.clone()).await,
            Finalizer::Cleanup(rest_path) => rest_path.cleanup(ctx.clone()).await,
        }
    })
    .await
    .map_err(|e| Error::FinalizerError(Box::new(e)))
}

fn error_policy(restpath: Arc<RestEndPoint>, error: &Error, ctx: Arc<Context>) -> Action {
    warn!("reconcile failed: {:?}", error);
    ctx.metrics.reconcile_failure(&restpath, error);
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
    // Reconcile (for non-finalizer related changes)
    async fn reconcile(&self, ctx: Arc<Context>) -> Result<Action> {
        let client = ctx.client.clone();
        let recorder = ctx.diagnostics.read().await.recorder(client.clone(), self);
        let ns = self.namespace().unwrap();
        let name = self.name_any();
        let restpaths: Api<RestEndPoint> = Api::namespaced(client, &ns);
        let mut conditions: Vec<ApplicationCondition> = Vec::new();
        let mut values = serde_json::json!({"input":{},"read":{},"write":{}});

        // Read the inputs first
        if let Some(inputs) = self.spec.clone().inputs {
            for input in inputs {
                if let Some(secret) = input.secret_ref {
                    let my_ns = if std::env::var("MULTI_TENANT").unwrap_or_else(|_| "true".to_string()).to_lowercase() == "true".to_string() {
                        if secret.namespace.is_some() {
                            recorder.publish(Event {
                                type_: EventType::Warning,
                                reason: "IgnoredNamespace".into(),
                                note: Some(format!("Ignoring namespace from Input '{}' as the operator run in multi-tenant mode",input.name)),
                                action: "readingInput".into(),
                                secondary: None,
                            }).await.map_err(Error::KubeError)?;
                        }
                        ns.clone()
                    } else if let Some(local_ns) = secret.namespace { local_ns } else { ns.clone() };
                    let mut secrets = SecretHandler::new(&ctx.client.clone(), &my_ns);
                    if secrets.have(&secret.name).await {
                        let my_secret = secrets.get(&secret.name).await.unwrap();
                        values["input"][input.name] = serde_json::json!({
                            "metadata": my_secret.metadata,
                            "data": my_secret.data
                        });
                    } else if secret.optional.unwrap_or(false) {
                        recorder.publish(Event {
                            type_: EventType::Normal,
                            reason: "IgnoredInput".into(),
                            note: Some(format!("Ignoring not found secret for Input '{}'",input.name)),
                            action: "readingInput".into(),
                            secondary: None,
                        }).await.map_err(Error::KubeError)?;
                        conditions.push(ApplicationCondition::input_missing(&format!("Input '{}' Secret {}.{} not found",input.name,my_ns,secret.name)));
                        values["input"][input.name] = serde_json::json!({});
                    } else {
                        recorder.publish(Event {
                            type_: EventType::Normal,
                            reason: "MissingSecret".into(),
                            note: Some(format!("Secret '{}' not found for Input '{}'",secret.name, input.name)),
                            action: "readingInput".into(),
                            secondary: None,
                        }).await.map_err(Error::KubeError)?;
                        conditions.push(ApplicationCondition::input_failed(&format!("Input '{}' Secret {}.{} not found",input.name,my_ns,secret.name)));
                    }
                } else if let Some(cfgmap) = input.config_map_ref {
                    let my_ns = if std::env::var("MULTI_TENANT").unwrap_or_else(|_| "true".to_string()).to_lowercase() == "true".to_string() {
                        if cfgmap.namespace.is_some() {
                            recorder.publish(Event {
                                type_: EventType::Warning,
                                reason: "IgnoredNamespace".into(),
                                note: Some(format!("Ignoring namespace from Input '{}' as the operator run in multi-tenant mode",input.name)),
                                action: "readingInput".into(),
                                secondary: None,
                            }).await.map_err(Error::KubeError)?;
                        }
                        ns.clone()
                    } else if let Some(local_ns) = cfgmap.namespace { local_ns } else { ns.clone() };
                    let mut maps = ConfigMapHandler::new(&ctx.client.clone(), &my_ns);
                    if maps.have(&cfgmap.name).await {
                        let my_cfg = maps.get(&cfgmap.name).await.unwrap();
                        values["input"][input.name] = serde_json::json!({
                            "metadata": my_cfg.metadata,
                            "data": my_cfg.data,
                            "binaryData": my_cfg.binary_data
                        });
                    } else if cfgmap.optional.unwrap_or(false) {
                        recorder.publish(Event {
                            type_: EventType::Normal,
                            reason: "IgnoredInput".into(),
                            note: Some(format!("Ignoring not found ConfigMap for Input '{}'",input.name)),
                            action: "readingInput".into(),
                            secondary: None,
                        }).await.map_err(Error::KubeError)?;
                        conditions.push(ApplicationCondition::input_missing(&format!("Input '{}' ConfigMap {}.{} not found",input.name,my_ns,cfgmap.name)));
                        values["input"][input.name] = serde_json::json!({});
                    } else {
                        recorder.publish(Event {
                            type_: EventType::Normal,
                            reason: "MissingConfigMap".into(),
                            note: Some(format!("ConfigMap '{}' not found for Input '{}'",cfgmap.name, input.name)),
                            action: "readingInput".into(),
                            secondary: None,
                        }).await.map_err(Error::KubeError)?;
                        conditions.push(ApplicationCondition::input_failed(&format!("Input '{}' ConfigMap {}.{} not found",input.name,my_ns,cfgmap.name)));
                    }
                } else {
                    // First send an event about the issue
                    recorder.publish(Event {
                        type_: EventType::Warning,
                        reason: "EmptyInput".into(),
                        note: Some(format!("Input '{}' have no source",input.name)),
                        action: "Fail".into(),
                        secondary: None,
                    }).await.map_err(Error::KubeError)?;
                    // Then update the status of the object
                    conditions.push(ApplicationCondition::input_failed(&format!("Input '{}' have no source",input.name)));
                    conditions.push(ApplicationCondition::not_ready(&format!("Input '{}' have no source",input.name)));
                    let new_status = Patch::Apply(json!({
                        "apiVersion": "kuberest.solidite.fr/v1",
                        "kind": "RestEndPoint",
                        "status": RestEndPointStatus { conditions, owned: self.owned(), owned_target: self.owned_target() }
                    }));
                    let ps = PatchParams::apply(RESTPATH_FINALIZER).force();
                    let _o = restpaths.patch_status(&name, &ps, &new_status).await.map_err(Error::KubeError)?;
                    // Finally fail the object
                    return Err(Error::IllegalRestEndPoint);
                }
            }
        }
        // Validate that reading went Ok
        if conditions.iter().any(|c| c.condition_type!=ConditionsType::InputMissing) {
            let msg = "Some input failed";
            conditions.push(ApplicationCondition::not_ready(msg));
            // Only update the status if it has changed
            if ! if let Some(status) = self.status.clone() {
                status.conditions.len() == conditions.len() && status.conditions.iter().any(|c| c.condition_type ==ConditionsType::Ready && c.message==msg)
            } else {false} {
                let new_status = Patch::Apply(json!({
                    "apiVersion": "kuberest.solidite.fr/v1",
                    "kind": "RestEndPoint",
                    "status": RestEndPointStatus { conditions, owned: self.owned(), owned_target: self.owned_target() }
                }));
                let ps = PatchParams::apply(RESTPATH_FINALIZER).force();
                let _o = restpaths.patch_status(&name, &ps, &new_status).await.map_err(Error::KubeError)?;
            }
            let next = if let Some(freq) = self.spec.check_frequency {freq} else {5*60};
            return Ok(Action::requeue(Duration::from_secs(next)));
        }

        // Setup the template engine then the httpClient
        let mut hbs = HandleBars::new();
        hbs.setup();
        let mut rest = RestClient::new(self.spec.client.baseurl.clone().as_str());
        if let Some(headers) = self.spec.client.headers.clone() {
            for (key,value) in headers {
                rest = rest.add_header(&template!(key.as_str(),hbs,&values,conditions,recorder), &template!(value.as_str(),hbs,&values,conditions,recorder));
            }
        }
        rest = rest.add_header_json();
        let cnd = conditions.clone();
        // Validate that client setup went Ok
        if cnd.iter().any(|c| c.condition_type!=ConditionsType::InputMissing) {
            let msg = "Client setup failed";
            conditions.push(ApplicationCondition::not_ready(msg));
            // Only update the status if it has changed
            if ! if let Some(status) = self.status.clone() {
                status.conditions.len() == conditions.len() && status.conditions.iter().any(|c| c.condition_type ==ConditionsType::Ready && c.message==msg)
            } else {false} {
                let new_status = Patch::Apply(json!({
                    "apiVersion": "kuberest.solidite.fr/v1",
                    "kind": "RestEndPoint",
                    "status": RestEndPointStatus { conditions, owned: self.owned(), owned_target: self.owned_target() }
                }));
                let ps = PatchParams::apply(RESTPATH_FINALIZER).force();
                let _o = restpaths.patch_status(&name, &ps, &new_status).await.map_err(Error::KubeError)?;
            }
            let next = if let Some(freq) = self.spec.check_frequency {freq} else {5*60};
            return Ok(Action::requeue(Duration::from_secs(next)));
        }

        // Handle each Reads
        if let Some(reads) = self.spec.reads.clone() {
            for group in reads {
                values["read"][group.name.clone()] = serde_json::json!({});
                let path = template!(group.path.as_str(),hbs,&values,conditions,recorder);
                for read in group.items {
                    values["read"][group.name.clone()][read.name] = rest.clone().obj_read(ReadMethod::Get, &path.as_str(), &template!(read.key.as_str(),hbs,&values,conditions,recorder)).unwrap_or_else(|e| {
                        tokio::task::block_in_place(|| {Handle::current().block_on(async {
                            recorder.publish(Event {
                                type_: EventType::Warning,
                                reason: format!("Failed reading: read.{}.{}",group.name.clone(),read.name),
                                note: Some(format!("{e}")),
                                action: "reading".into(),
                                secondary: None,
                            }).await.map_err(Error::KubeError).unwrap();
                        })});
                        conditions.push(ApplicationCondition::read_failed(&format!("Reading read.{}.{} raised {e}",group.name.clone(),read.name)));
                        json!({})
                    });
                }
            }
        }
        // Validate that all reads went Ok
        if cnd.iter().any(|c| c.condition_type!=ConditionsType::InputMissing) {
            let msg = "Some read have failed";
            conditions.push(ApplicationCondition::not_ready(msg));
            // Only update the status if it has changed
            if ! if let Some(status) = self.status.clone() {
                status.conditions.len() == conditions.len() && status.conditions.iter().any(|c| c.condition_type ==ConditionsType::Ready && c.message==msg)
            } else {false} {
                let new_status = Patch::Apply(json!({
                    "apiVersion": "kuberest.solidite.fr/v1",
                    "kind": "RestEndPoint",
                    "status": RestEndPointStatus { conditions, owned: self.owned(), owned_target: self.owned_target() }
                }));
                let ps = PatchParams::apply(RESTPATH_FINALIZER).force();
                let _o = restpaths.patch_status(&name, &ps, &new_status).await.map_err(Error::KubeError)?;
            }
            let next = if let Some(freq) = self.spec.check_frequency {freq} else {5*60};
            return Ok(Action::requeue(Duration::from_secs(next)));
        }

        // TODO: Handle each Writes
        let mut target_new: Vec<OwnedRestPoint> = Vec::new();
        /*if let Some(writes) = self.spec.writes.clone() {
            for group in writes {

            }
        }*/




        // TODO: delete old owned writes




        // Verify that all writes when OK
        if cnd.iter().any(|c| c.condition_type!=ConditionsType::InputMissing && c.condition_type!=ConditionsType::WriteAlreadyExist) {
            let msg = "Some read have failed";
            conditions.push(ApplicationCondition::not_ready(msg));
            // Only update the status if it has changed
            if ! if let Some(status) = self.status.clone() {
                status.conditions.len() == conditions.len() && status.conditions.iter().any(|c| c.condition_type ==ConditionsType::Ready && c.message==msg)
            } else {false} {
                let new_status = Patch::Apply(json!({
                    "apiVersion": "kuberest.solidite.fr/v1",
                    "kind": "RestEndPoint",
                    "status": RestEndPointStatus { conditions, owned: self.owned(), owned_target: target_new }
                }));
                let ps = PatchParams::apply(RESTPATH_FINALIZER).force();
                let _o = restpaths.patch_status(&name, &ps, &new_status).await.map_err(Error::KubeError)?;
            }
            let next = if let Some(freq) = self.spec.check_frequency {freq} else {5*60};
            return Ok(Action::requeue(Duration::from_secs(next)));
        }

        // Finally: handle Outputs
        let mut owned_new: Vec<OwnedObjects> = Vec::new();
        if let Some(outputs) = self.spec.outputs.clone() {
            for output in outputs {
                let my_ns = if std::env::var("MULTI_TENANT").unwrap_or_else(|_| "true".to_string()).to_lowercase() == "true".to_string() {
                    if output.metadata.namespace.is_some() {
                        recorder.publish(Event {
                            type_: EventType::Warning,
                            reason: "IgnoredNamespace".into(),
                            note: Some(format!("Ignoring namespace from Output '{}' as the operator run in multi-tenant mode",output.metadata.name)),
                            action: "readingInput".into(),
                            secondary: None,
                        }).await.map_err(Error::KubeError)?;
                    }
                    ns.clone()
                } else if let Some(local_ns) = output.clone().metadata.namespace { local_ns } else { ns.clone() };
                let mut my_values:HashMap<String, String> = HashMap::new();
                for (key,val) in output.clone().data {
                    my_values.insert(template!(key.as_str(),hbs,&values,conditions,recorder), template!(val.as_str(),hbs,&values,conditions,recorder));
                }
                if output.kind == Kind::Secret {
                    let mut secrets = SecretHandler::new(&ctx.client.clone(), &my_ns);
                    if self.owned().clone().into_iter().any(|o| o.kind==output.kind && o.name==output.metadata.name && o.namespace == my_ns ) {
                        let myself = self.owned().clone().into_iter().find(|o| o.kind==output.kind && o.name==output.metadata.name && o.namespace == my_ns ).unwrap();
                        if secrets.have_uid(&myself.name,&myself.uid).await {
                            let _ = update!(secrets, "Secret", output, my_ns,&my_values,conditions,recorder);
                            owned_new.push(myself);
                        } else if secrets.have(&myself.name).await {
                            let _ = update!(secrets, "Secret", output, my_ns,&my_values,conditions,recorder);
                            if output.teardown.unwrap_or(true) {
                                recorder.publish(Event {
                                    type_: EventType::Warning,
                                    reason: "OutputAlreadyExist".into(),
                                    note: Some(format!("Secret output '{}.{}' already exist, won't take ownership.",my_ns, output.metadata.name)),
                                    action: "outputSecret".into(),
                                    secondary: None,
                                }).await.map_err(Error::KubeError)?;
                                conditions.push(ApplicationCondition::output_exist(&format!("Secret output '{}.{}' already exist, won't take ownership.",my_ns, output.metadata.name)));
                            }
                        } else {
                            let own = if output.teardown.unwrap_or(true) && my_ns==self.namespace().unwrap_or(my_ns.clone()) {Some(self)} else {None};
                            if let Some(sec) = create!(secrets, "Secret", own, output, my_ns,&my_values,conditions,recorder) {
                                if output.teardown.unwrap_or(true) {
                                    owned_new.push(OwnedObjects::secret(sec.metadata.name.unwrap().as_str(), sec.metadata.namespace.unwrap().as_str(), sec.metadata.uid.unwrap().as_str()));
                                }
                            }
                        }
                    } else {
                        if secrets.have(&output.metadata.name).await {
                            let _ = update!(secrets, "Secret", output, my_ns,&my_values,conditions,recorder);
                            if output.teardown.unwrap_or(true) {
                                recorder.publish(Event {
                                    type_: EventType::Warning,
                                    reason: "OutputAlreadyExist".into(),
                                    note: Some(format!("Secret output '{}.{}' already exist, won't take ownership.",my_ns, output.metadata.name)),
                                    action: "outputSecret".into(),
                                    secondary: None,
                                }).await.map_err(Error::KubeError)?;
                                conditions.push(ApplicationCondition::output_exist(&format!("Secret output '{}.{}' already exist, won't take ownership.",my_ns, output.metadata.name)));
                            }
                        } else {
                            let own = if output.teardown.unwrap_or(true) && my_ns==self.namespace().unwrap_or(my_ns.clone()) {Some(self)} else {None};
                            if let Some(sec) = create!(secrets, "Secret", own, output.clone(), my_ns,&my_values,conditions,recorder) {
                                if output.teardown.unwrap_or(true) {
                                    owned_new.push(OwnedObjects::secret(sec.metadata.name.unwrap().as_str(), sec.metadata.namespace.unwrap().as_str(), sec.metadata.uid.unwrap().as_str()));
                                }
                            }
                        }
                    }
                } else if output.kind == Kind::ConfigMap {
                    let mut cms = ConfigMapHandler::new(&ctx.client.clone(), &my_ns);
                    if self.owned().clone().into_iter().any(|o| o.kind==output.kind && o.name==output.metadata.name && o.namespace == my_ns ) {
                        let myself = self.owned().clone().into_iter().find(|o| o.kind==output.kind && o.name==output.metadata.name && o.namespace == my_ns ).unwrap();
                        if cms.have_uid(&myself.name,&myself.uid).await {
                            let _ = update!(cms, "ConfigMap", output, my_ns,&my_values,conditions,recorder);
                            owned_new.push(myself);
                        } else if cms.have(&myself.name).await {
                            let _ = update!(cms, "ConfigMap", output, my_ns,&my_values,conditions,recorder);
                            if output.teardown.unwrap_or(true) {
                                recorder.publish(Event {
                                    type_: EventType::Warning,
                                    reason: "OutputAlreadyExist".into(),
                                    note: Some(format!("ConfigMap output '{}.{}' already exist, won't take ownership.",my_ns, output.metadata.name)),
                                    action: "outputConfigMap".into(),
                                    secondary: None,
                                }).await.map_err(Error::KubeError)?;
                                conditions.push(ApplicationCondition::output_exist(&format!("ConfigMap output '{}.{}' already exist, won't take ownership.",my_ns, output.metadata.name)));
                            }
                        } else {
                            let own = if output.teardown.unwrap_or(true) && my_ns==self.namespace().unwrap_or(my_ns.clone()) {Some(self)} else {None};
                            if let Some(sec) = create!(cms, "ConfigMap", own, output, my_ns,&my_values,conditions,recorder) {
                                if output.teardown.unwrap_or(true) {
                                    owned_new.push(OwnedObjects::secret(sec.metadata.name.unwrap().as_str(), sec.metadata.namespace.unwrap().as_str(), sec.metadata.uid.unwrap().as_str()));
                                }
                            }
                        }
                    } else {
                        if cms.have(&output.metadata.name).await {
                            let _ = update!(cms, "ConfigMap", output, my_ns,&my_values,conditions,recorder);
                            if output.teardown.unwrap_or(true) {
                                recorder.publish(Event {
                                    type_: EventType::Warning,
                                    reason: "OutputAlreadyExist".into(),
                                    note: Some(format!("ConfigMap output '{}.{}' already exist, won't take ownership.",my_ns, output.metadata.name)),
                                    action: "outputConfigMap".into(),
                                    secondary: None,
                                }).await.map_err(Error::KubeError)?;
                                conditions.push(ApplicationCondition::output_exist(&format!("ConfigMap output '{}.{}' already exist, won't take ownership.",my_ns, output.metadata.name)));
                            }
                        } else {
                            let own = if output.teardown.unwrap_or(true) && my_ns==self.namespace().unwrap_or(my_ns.clone()) {Some(self)} else {None};
                            if let Some(sec) = create!(cms, "ConfigMap", own, output.clone(), my_ns,&my_values,conditions,recorder) {
                                if output.teardown.unwrap_or(true) {
                                    owned_new.push(OwnedObjects::secret(sec.metadata.name.unwrap().as_str(), sec.metadata.namespace.unwrap().as_str(), sec.metadata.uid.unwrap().as_str()));
                                }
                            }
                        }
                    }
                }
            }
        }
        // Handle every owned object that is not in the new list
        for obj in self.clone().owned() {
            if ! owned_new.clone().into_iter().any(|n| n.kind == obj.kind && n.namespace == obj.namespace && n.name == obj.namespace) {
                if obj.kind == Kind::Secret {
                    let mut secrets = SecretHandler::new(&ctx.client.clone(), &obj.namespace);
                    if secrets.have_uid(&obj.name, &obj.uid).await {
                        secrets.delete(obj.name.as_str()).await.unwrap_or_else(|e| {
                            tokio::task::block_in_place(|| {Handle::current().block_on(async {
                                recorder.publish(Event {
                                    type_: EventType::Warning,
                                    reason: format!("Failed deleting: {}.{}",obj.namespace,obj.name),
                                    note: Some(format!("{e}")),
                                    action: "deleting".into(),
                                    secondary: None,
                                }).await.map_err(Error::KubeError).unwrap();
                            })});
                            conditions.push(ApplicationCondition::output_delete_failed(&format!("Failed deleting: {}.{}",obj.namespace,obj.name)));
                            owned_new.push(obj.clone());
                        })
                    }
                } else if obj.kind == Kind::ConfigMap {
                    let mut secrets = ConfigMapHandler::new(&ctx.client.clone(), &obj.namespace);
                    if secrets.have_uid(&obj.name, &obj.uid).await {
                        secrets.delete(obj.name.as_str()).await.unwrap_or_else(|e| {
                            tokio::task::block_in_place(|| {Handle::current().block_on(async {
                                recorder.publish(Event {
                                    type_: EventType::Warning,
                                    reason: format!("Failed deleting: {}.{}",obj.namespace,obj.name),
                                    note: Some(format!("{e}")),
                                    action: "deleting".into(),
                                    secondary: None,
                                }).await.map_err(Error::KubeError).unwrap();
                            })});
                            conditions.push(ApplicationCondition::output_delete_failed(&format!("Failed deleting: {}.{}",obj.namespace,obj.name)));
                            owned_new.push(obj.clone());
                        })
                    }
                }
            }
        }

        // Verify that everything went fine and update the status accordingly
        if conditions.iter().any(|c| c.condition_type!=ConditionsType::InputMissing && c.condition_type!=ConditionsType::WriteAlreadyExist&& c.condition_type!=ConditionsType::OutputAlreadyExist ) {
            let msg = "Some output have failed";
            conditions.push(ApplicationCondition::not_ready(msg));
            // Only update the status if it has changed
            if ! if let Some(status) = self.status.clone() {
                status.conditions.len() == conditions.len() && status.conditions.iter().any(|c| c.condition_type ==ConditionsType::Ready && c.message==msg)
            } else {false} {
                let new_status = Patch::Apply(json!({
                    "apiVersion": "kuberest.solidite.fr/v1",
                    "kind": "RestEndPoint",
                    "status": RestEndPointStatus { conditions, owned: owned_new, owned_target: target_new }
                }));
                let ps = PatchParams::apply(RESTPATH_FINALIZER).force();
                let _o = restpaths.patch_status(&name, &ps, &new_status).await.map_err(Error::KubeError)?;
            }
        } else {
            let msg = "All done";
            conditions.push(ApplicationCondition::is_ready(msg));
            // Only update the status if it has changed
            if ! if let Some(status) = self.status.clone() {
                status.conditions.len() == conditions.len() && status.conditions.iter().any(|c| c.condition_type ==ConditionsType::Ready && c.message==msg)
            } else {false} {
                let new_status = Patch::Apply(json!({
                    "apiVersion": "kuberest.solidite.fr/v1",
                    "kind": "RestEndPoint",
                    "status": RestEndPointStatus { conditions, owned: owned_new, owned_target: target_new }
                }));
                let ps = PatchParams::apply(RESTPATH_FINALIZER).force();
                let _o = restpaths.patch_status(&name, &ps, &new_status).await.map_err(Error::KubeError)?;
            }
        }
        let next = if let Some(freq) = self.spec.check_frequency {freq} else {5*60};
        Ok(Action::requeue(Duration::from_secs(next)))
    }

    // Finalizer cleanup (the object was deleted, ensure nothing is orphaned)
    async fn cleanup(&self, ctx: Arc<Context>) -> Result<Action> {
        let client = ctx.client.clone();
        ctx.diagnostics.write().await.last_event = Utc::now();
        let reporter = ctx.diagnostics.read().await.reporter.clone();
        let recorder = Recorder::new(client.clone(), reporter, self.object_ref(&()));
        let ns = self.namespace().unwrap();
        let name = self.name_any();
        let restpaths: Api<RestEndPoint> = Api::namespaced(client, &ns);
        let mut conditions: Vec<ApplicationCondition> = Vec::new();
        let mut owned_new: Vec<OwnedObjects> = Vec::new();
        let mut target_new: Vec<OwnedRestPoint> = Vec::new();

        // TODO: delete writes

        // Delete owned objects
        if let Some(status) = self.status.clone() {
            for obj in status.owned {
                if obj.kind == Kind::Secret {
                    let mut secrets = SecretHandler::new(&ctx.client.clone(), &obj.namespace);
                    if secrets.have_uid(&obj.name, &obj.uid).await {
                        secrets.delete(obj.name.as_str()).await.unwrap_or_else(|e| {
                            tokio::task::block_in_place(|| {Handle::current().block_on(async {
                                recorder.publish(Event {
                                    type_: EventType::Warning,
                                    reason: format!("Failed deleting: {}.{}",obj.namespace,obj.name),
                                    note: Some(format!("{e}")),
                                    action: "deleting".into(),
                                    secondary: None,
                                }).await.map_err(Error::KubeError).unwrap();
                            })});
                            conditions.push(ApplicationCondition::output_delete_failed(&format!("Failed deleting: {}.{}",obj.namespace,obj.name)));
                            owned_new.push(obj.clone());
                        })
                    }
                } else if obj.kind == Kind::ConfigMap {
                    let mut secrets = ConfigMapHandler::new(&ctx.client.clone(), &obj.namespace);
                    if secrets.have_uid(&obj.name, &obj.uid).await {
                        secrets.delete(obj.name.as_str()).await.unwrap_or_else(|e| {
                            tokio::task::block_in_place(|| {Handle::current().block_on(async {
                                recorder.publish(Event {
                                    type_: EventType::Warning,
                                    reason: format!("Failed deleting: {}.{}",obj.namespace,obj.name),
                                    note: Some(format!("{e}")),
                                    action: "deleting".into(),
                                    secondary: None,
                                }).await.map_err(Error::KubeError).unwrap();
                            })});
                            conditions.push(ApplicationCondition::output_delete_failed(&format!("Failed deleting: {}.{}",obj.namespace,obj.name)));
                            owned_new.push(obj.clone());
                        })
                    }
                }
            }
        }
        if conditions.len()>0 || owned_new.len()>0 || target_new.len()>0 {
            let msg = "Some teardown failed";
            conditions.push(ApplicationCondition::not_ready(msg));
            // Only update the status if it has changed
            if ! if let Some(status) = self.status.clone() {
                status.conditions.len() == conditions.len() && status.conditions.iter().any(|c| c.condition_type ==ConditionsType::Ready && c.message==msg)
            } else {false} {
                let new_status = Patch::Apply(json!({
                    "apiVersion": "kuberest.solidite.fr/v1",
                    "kind": "RestEndPoint",
                    "status": RestEndPointStatus { conditions, owned: owned_new, owned_target: target_new }
                }));
                let ps = PatchParams::apply(RESTPATH_FINALIZER).force();
                let _o = restpaths.patch_status(&name, &ps, &new_status).await.map_err(Error::KubeError)?;
            }
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
            reporter: "restpath-controller".into(),
        }
    }
}
impl Diagnostics {
    fn recorder(&self, client: Client, restpath: &RestEndPoint) -> Recorder {
        Recorder::new(client, self.reporter.clone(), restpath.object_ref(&()))
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
    let restpaths = Api::<RestEndPoint>::all(client.clone());
    if let Err(e) = restpaths.list(&ListParams::default().limit(1)).await {
        error!("CRD is not queryable; {e:?}. Is the CRD installed?");
        info!("Installation: cargo run --bin crdgen | kubectl apply -f -");
        std::process::exit(1);
    }
    Controller::new(restpaths, Config::default().any_semantic())
        .shutdown_on_signal()
        .run(reconcile, error_policy, state.to_context(client))
        .filter_map(|x| async move { std::result::Result::ok(x) })
        .for_each(|_| futures::future::ready(()))
        .await;
}

// Mock tests relying on fixtures.rs and its primitive apiserver mocks
#[cfg(test)]
mod test {
    use super::{/* error_policy, */ reconcile, Context, RestEndPoint};
    use crate::fixtures::{timeout_after_1s, Scenario};
    use std::sync::Arc;

    #[tokio::test]
    async fn restpath_without_finalizer_gets_a_finalizer() {
        let (testctx, fakeserver, _) = Context::test();
        let restpath = RestEndPoint::test();
        let mocksrv = fakeserver.run(Scenario::FinalizerCreation(restpath.clone()));
        reconcile(Arc::new(restpath), testctx).await.expect("reconciler");
        timeout_after_1s(mocksrv).await;
    }

    #[tokio::test]
    async fn finalized_restpath_causes_status_patch() {
        let (testctx, fakeserver, _) = Context::test();
        let restpath = RestEndPoint::test().finalized();
        let mocksrv = fakeserver.run(Scenario::StatusPatch(restpath.clone()));
        reconcile(Arc::new(restpath), testctx).await.expect("reconciler");
        timeout_after_1s(mocksrv).await;
    }

/*
    #[tokio::test]
    async fn finalized_restpath_with_hide_causes_event_and_hide_patch() {
        let (testctx, fakeserver, _) = Context::test();
        let restpath = RestEndPoint::test().finalized().needs_hide();
        let scenario = Scenario::EventPublishThenStatusPatch("HideRequested".into(), restpath.clone());
        let mocksrv = fakeserver.run(scenario);
        reconcile(Arc::new(restpath), testctx).await.expect("reconciler");
        timeout_after_1s(mocksrv).await;
    }
*/
    #[tokio::test]
    async fn finalized_restpath_with_delete_timestamp_causes_delete() {
        let (testctx, fakeserver, _) = Context::test();
        let restpath = RestEndPoint::test().finalized().needs_delete();
        let mocksrv = fakeserver.run(Scenario::Cleanup("DeleteRequested".into(), restpath.clone()));
        reconcile(Arc::new(restpath), testctx).await.expect("reconciler");
        timeout_after_1s(mocksrv).await;
    }
/*
    #[tokio::test]
    async fn illegal_restpath_reconcile_errors_which_bumps_failure_metric() {
        let (testctx, fakeserver, _registry) = Context::test();
        let restpath = Arc::new(RestEndPoint::illegal().finalized());
        let mocksrv = fakeserver.run(Scenario::RadioSilence);
        let res = reconcile(restpath.clone(), testctx.clone()).await;
        timeout_after_1s(mocksrv).await;
        assert!(res.is_err(), "apply reconciler fails on illegal restpath");
        let err = res.unwrap_err();
        assert!(err.to_string().contains("IllegalRestEndPoint"));
        // calling error policy with the reconciler error should cause the correct metric to be set
        error_policy(restpath.clone(), &err, testctx.clone());
        //dbg!("actual metrics: {}", registry.gather());
        let failures = testctx
            .metrics
            .failures
            .with_label_values(&["illegal", "finalizererror(applyfailed(illegalrestpathument))"])
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

        // create a test restpath
        let restpath = RestEndPoint::test().finalized().needs_hide();
        let restpaths: Api<RestEndPoint> = Api::namespaced(client.clone(), "default");
        let ssapply = PatchParams::apply("ctrltest");
        let patch = Patch::Apply(restpath.clone());
        restpaths.patch("test", &ssapply, &patch).await.unwrap();

        // reconcile it (as if it was just applied to the cluster like this)
        reconcile(Arc::new(restpath), ctx).await.unwrap();

        // verify side-effects happened
        let output = restpaths.get_status("test").await.unwrap();
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
