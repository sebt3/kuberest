use crate::httphandler::{CreateMethod, DeleteMethod, ReadMethod, UpdateMethod};
use chrono::{DateTime, Utc};
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
    pub teardown: Option<bool>,
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
    pub teardown: Option<bool>,
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
    pub kind: Kind,
    /// The metadata of the Object (requiered: name)
    pub metadata: Metadata,
    /// Data of the Output (will be base64-encoded for secret Secrets)
    pub data: HashMap<String, String>,
    /// Delete the Secret on RestEndPoint deletion (default: true)
    pub teardown: Option<bool>,
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
