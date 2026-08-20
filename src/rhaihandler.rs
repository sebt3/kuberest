use crate::{
    Error::{self, *},
    handlebarshandler::{self, HandleBars},
    passwordhandler::Passwords,
};
use vynil_core::http::http_rhai_register;

/// Wraps vynil_core's Rhai engine setup (log/json/yaml/base64/hashes/...), adding kuberest's
/// own gen_password/gen_password_alphanum (weight-based, matching the public `password_generator`
/// CRD field - vynil-core's `password` feature is deliberately left disabled to avoid a name
/// collision with its own minimum-count based generator), HandleBars and RestClient.
pub struct Script(pub vynil_core::engine::Script);

impl std::ops::Deref for Script {
    type Target = vynil_core::engine::Script;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for Script {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Script {
    #[must_use]
    pub fn new() -> Script {
        let mut inner = vynil_core::engine::Script::new_bare(vec![]);
        inner
            .engine
            .register_fn("gen_password", |len: u32| -> String {
                Passwords::new().generate(len, 6, 2, 2)
            })
            .register_fn("gen_password_alphanum", |len: u32| -> String {
                Passwords::new().generate(len, 8, 2, 0)
            });
        inner
            .engine
            .register_type_with_name::<HandleBars>("HandleBars")
            .register_fn("new_hbs", handlebarshandler::new_hbs)
            .register_fn("register_template", HandleBars::rhai_register_template)
            .register_fn("render_from", HandleBars::rhai_render);
        http_rhai_register(&mut inner.engine);
        Script(inner)
    }

    pub fn eval(&mut self, script: &str) -> Result<serde_json::Value, Error> {
        match self
            .0
            .engine
            .eval_with_scope::<rhai::Map>(&mut self.0.ctx, script)
        {
            Ok(v) => {
                let value: serde_json::Value =
                    serde_json::from_str(&serde_json::to_string(&v).unwrap()).unwrap();
                Ok(value)
            }
            Err(e) => Err(RhaiError(e)),
        }
    }
}
