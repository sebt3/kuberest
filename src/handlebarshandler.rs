use crate::passwordhandler::Passwords;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use handlebars::{handlebars_helper, Handlebars};
use handlebars_misc_helpers::new_hbs;
pub use serde_json::Value;
use tracing::*;

handlebars_helper!(base64_decode: |arg:Value| String::from_utf8(STANDARD.decode(arg.as_str().unwrap_or_else(|| {
    warn!("handlebars::base64_decode received a non-string parameter: {:?}",arg);
    ""
}).to_string()).unwrap_or_else(|e| {
    warn!("handlebars::base64_decode failed to decode with: {e:?}");
    vec![]
})).unwrap_or_else(|e| {
    warn!("handlebars::base64_decode failed to convert to string with: {e:?}");
    String::new()
}));
handlebars_helper!(base64_encode: |arg:Value| STANDARD.encode(arg.as_str().unwrap_or_else(|| {
    warn!("handlebars::base64_encode received a non-string parameter: {:?}",arg);
    ""
}).to_string()));
handlebars_helper!(header_basic: |username:Value,password:Value| format!("Basic {}",STANDARD.encode(format!("{}:{}",username.as_str().unwrap_or_else(|| {
    warn!("handlebars::header_basic received a non-string username: {:?}",username);
    ""
}),password.as_str().unwrap_or_else(|| {
    warn!("handlebars::header_basic received a non-string password: {:?}",password);
    ""
})))));
handlebars_helper!(gen_password:  |len:u32| Passwords::new().generate(len, 6, 2, 2));
handlebars_helper!(gen_password_alphanum:  |len:u32| Passwords::new().generate(len, 8, 2, 0));

#[derive(Clone, Debug)]
pub struct HandleBars<'a> {
    engine: Handlebars<'a>,
}
impl HandleBars<'_> {
    #[must_use]
    pub fn new() -> HandleBars<'static> {
        let mut res = HandleBars { engine: new_hbs() };
        res.engine
            .register_helper("base64_decode", Box::new(base64_decode));
        res.engine
            .register_helper("base64_encode", Box::new(base64_encode));
        res.engine.register_helper("header_basic", Box::new(header_basic));
        res.engine.register_helper("gen_password", Box::new(gen_password));
        res.engine
            .register_helper("gen_password_alphanum", Box::new(gen_password_alphanum));
        // TODO: add more helpers
        res
    }

    pub fn register_template(&mut self, name: &str, template: &str) -> Result<(), handlebars::TemplateError> {
        self.engine.register_template_string(name, template)
    }

    pub fn register_template_rhai(&mut self, name: String, template: String) -> bool {
        match self.register_template(name.as_str(), template.as_str()) {
            Ok(()) => true,
            Err(e) => {
                debug!("Registring template from rhai generated: {e:?}");
                false
            }
        }
    }

    pub fn render(
        &mut self,
        template: &str,
        data: &Value,
    ) -> std::result::Result<String, handlebars::RenderError> {
        self.engine.render_template(template, data)
    }

    pub fn render_from_rhai(&mut self, template: String, data: rhai::Map) -> String {
        self.engine
            .render_template(template.as_str(), &data)
            .unwrap_or_else(|e| {
                debug!("Rendering template from rhai generated: {e:?}");
                String::new()
            })
    }
}
