use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("SerializationError: {0}")]
    SerializationError(#[source] serde_json::Error),

    #[error("K8s error: {0}")]
    KubeError(#[source] kube::Error),

    #[error("Finalizer error: {0}")]
    // NB: awkward type because finalizer::Error embeds the reconciler error (which is this)
    // so boxing this error to break cycles
    FinalizerError(#[source] Box<kube::runtime::finalizer::Error<Error>>),

    #[error("Registering template failed with error: {0}")]
    HbsTemplateError(#[source] handlebars::TemplateError),
    #[error("Renderer error: {0}")]
    HbsRenderError(#[source] handlebars::RenderError),

    #[error("Rhai script error: {0}")]
    RhaiError(#[source] Box<rhai::EvalAltResult>),

    #[error("Reqwest error: {0}")]
    ReqwestError(#[source] reqwest::Error),

    #[error("Json decoding error: {0}")]
    JsonError(#[source] serde_json::Error),

    #[error("{0} query failed: {1}")]
    MethodFailed(String, u16, String),

    #[error("Unsupported method")]
    UnsupportedMethod,

    #[error("TeardownIncomplete")]
    TeardownIncomplete,

    #[error("IllegalRestEndPoint")]
    IllegalRestEndPoint,
}
pub type Result<T, E = Error> = std::result::Result<T, E>;

impl Error {
    pub fn metric_label(&self) -> String {
        format!("{self:?}").to_lowercase()
    }
}

/// Expose all restpath components used by main
pub mod restendpoint;
pub use crate::restendpoint::*;

/// Log and trace integrations
pub mod telemetry;

/// Metrics
mod metrics;
pub use metrics::Metrics;

mod handlebarshandler;
mod httphandler;
mod k8shandlers;
mod passwordhandler;
mod rhaihandler;

#[cfg(test)] pub mod fixtures;

#[macro_export]
macro_rules! template {
    ( $( $tmpl:expr, $hbs:expr, $values:expr, $conditions:expr, $recorder:expr ),* ) => {
        {   $(
            $hbs.clone().render($tmpl, $values).unwrap_or_else(|e| {
                $conditions.push(ApplicationCondition::template_failed(&format!("`{}` raised {e}",$tmpl)));
                tokio::task::block_in_place(|| {Handle::current().block_on(async {
                    $recorder.publish(Event {
                        type_: EventType::Warning,
                        reason: format!("Failed templating: {}",$tmpl),
                        note: Some(format!("{e}")),
                        action: "templating".into(),
                        secondary: None,
                    }).await.map_err(Error::KubeError).unwrap_or(());
                })});
                $tmpl.to_string()
            })
        )*}
    };
}

#[macro_export]
macro_rules! update {
    ( $list:expr, $type_obj:expr, $output:expr, $my_ns:expr, $my_values:expr, $conditions:expr, $recorder:expr ) => {
        match $list.update(&$output.metadata, $my_values).await {
            Ok(x) => Some(x),
            Err(e) => {
                $recorder
                    .publish(Event {
                        type_: EventType::Warning,
                        reason: format!(
                            "Failed to update {}: {}.{}",
                            $type_obj, $my_ns, $output.metadata.name
                        ),
                        note: Some(format!("{e}")),
                        action: "updating".into(),
                        secondary: None,
                    })
                    .await
                    .map_err(Error::KubeError)
                    .unwrap();
                $conditions.push(ApplicationCondition::output_failed(&format!(
                    "Patching {} {}.{} raised {e}",
                    $type_obj, $my_ns, $output.metadata.name
                )));
                None
            }
        }
    };
}
#[macro_export]
macro_rules! create {
    ( $list:expr, $type_obj:expr, $own:expr, $output:expr, $my_ns:expr, $my_values:expr, $conditions:expr, $recorder:expr ) => {
        match $list.create($own, &$output.clone().metadata, $my_values).await {
            Ok(x) => Some(x),
            Err(e) => {
                $recorder
                    .publish(Event {
                        type_: EventType::Warning,
                        reason: format!(
                            "Failed to create {}: {}.{}",
                            $type_obj, $my_ns, $output.metadata.name
                        ),
                        note: Some(format!("{e}")),
                        action: "updating".into(),
                        secondary: None,
                    })
                    .await
                    .map_err(Error::KubeError)
                    .unwrap();
                $conditions.push(ApplicationCondition::output_failed(&format!(
                    "Creating {} {}.{} raised {e}",
                    $type_obj, $my_ns, $output.metadata.name
                )));
                None
            }
        }
    };
}
