use handlebars_misc_helpers::new_hbs;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use handlebars::{handlebars_helper, Handlebars, RenderError};
pub use serde_json::Value;

handlebars_helper!(base64_decode: |arg:Value| String::from_utf8(STANDARD.decode(arg.as_str().unwrap().to_string()).unwrap()).unwrap());
handlebars_helper!(base64_encode: |arg:Value| STANDARD.encode(arg.as_str().unwrap().to_string()));

#[derive(Clone, Debug)]
pub struct HandleBars<'a> {
    engine: Handlebars<'a>,
}
impl HandleBars<'_> {
    #[must_use] pub fn new() -> HandleBars<'static> {
        HandleBars {
            engine: new_hbs(),
        }
    }
    pub fn setup(&mut self) {
        self.engine.register_helper("base64_decode", Box::new(base64_decode));
        self.engine.register_helper("base64_encode", Box::new(base64_encode));
        // TODO: add more helpers
    }
    pub fn render(&mut self, template: &str, data: &Value) -> std::result::Result<String, RenderError> {
        self.engine.render_template(template, data)
    }
}
