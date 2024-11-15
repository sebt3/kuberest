use crate::{hasheshandlers::Argon, passwordhandler::Passwords, Error, Result, RhaiRes};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use handlebars::{handlebars_helper, Handlebars};
use handlebars_misc_helpers::new_hbs;
pub use serde_json::Value;
use tracing::*;
// TODO: improve error management
handlebars_helper!(base64_decode: |arg:Value| String::from_utf8(STANDARD.decode(arg.as_str().unwrap_or_else(|| {
    warn!("handlebars::base64_decode received a non-string parameter: {:?}",arg);
    ""
})).unwrap_or_else(|e| {
    warn!("handlebars::base64_decode failed to decode with: {e:?}");
    vec![]
})).unwrap_or_else(|e| {
    warn!("handlebars::base64_decode failed to convert to string with: {e:?}");
    String::new()
}));
handlebars_helper!(base64_encode: |arg:Value| STANDARD.encode(arg.as_str().unwrap_or_else(|| {
    warn!("handlebars::base64_encode received a non-string parameter: {:?}",arg);
    ""
})));
handlebars_helper!(header_basic: |username:Value, password:Value| format!("Basic {}",STANDARD.encode(format!("{}:{}",username.as_str().unwrap_or_else(|| {
    warn!("handlebars::header_basic received a non-string username: {:?}",username);
    ""
}),password.as_str().unwrap_or_else(|| {
    warn!("handlebars::header_basic received a non-string password: {:?}",password);
    ""
})))));
handlebars_helper!(argon_hash: |password:Value| Argon::new().hash(password.as_str().unwrap_or_else(|| {
    warn!("handlebars::argon_hash received a non-string password: {:?}",password);
    ""
}).to_string()).unwrap_or_else(|e| {
    warn!("handlebars::argon_hash failed to convert to string with: {e:?}");
    String::new()
}));
handlebars_helper!(gen_password: |len:u32| Passwords::new().generate(len, 6, 2, 2));
handlebars_helper!(gen_password_alphanum:  |len:u32| Passwords::new().generate(len, 8, 2, 0));

#[derive(Clone, Debug)]
pub struct HandleBars<'a> {
    engine: Handlebars<'a>,
}
impl HandleBars<'_> {
    #[must_use]
    pub fn new() -> HandleBars<'static> {
        let mut engine = new_hbs();
        engine.register_helper("base64_decode", Box::new(base64_decode));
        engine.register_helper("base64_encode", Box::new(base64_encode));
        engine.register_helper("header_basic", Box::new(header_basic));
        engine.register_helper("argon_hash", Box::new(argon_hash));
        engine.register_helper("gen_password", Box::new(gen_password));
        engine.register_helper("gen_password_alphanum", Box::new(gen_password_alphanum));
        // TODO: add more helpers
        HandleBars { engine }
    }

    pub fn register_template(&mut self, name: &str, template: &str) -> Result<()> {
        self.engine
            .register_template_string(name, template)
            .map_err(Error::HbsTemplateError)
    }

    pub fn rhai_register_template(&mut self, name: String, template: String) -> RhaiRes<()> {
        self.register_template(name.as_str(), template.as_str())
            .map_err(|e| format!("{e}").into())
    }

    pub fn render(&mut self, template: &str, data: &Value) -> Result<String> {
        self.engine
            .render_template(template, data)
            .map_err(Error::HbsRenderError)
    }

    pub fn rhai_render(&mut self, template: String, data: rhai::Map) -> RhaiRes<String> {
        self.engine
            .render_template(template.as_str(), &data)
            .map_err(|e| format!("{e}").into())
    }
}
