use crate::{
    handlebarshandler::HandleBars,
    hasheshandlers::Argon,
    httphandler::RestClient,
    passwordhandler::Passwords,
    rhai_err,
    Error::{self, *},
    RhaiRes,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rhai::{Dynamic, Engine, ImmutableString, Map, Module, Scope};
use serde::Deserialize;

#[derive(Debug)]
pub struct Script {
    pub engine: Engine,
    pub ctx: Scope<'static>,
}

impl Script {
    #[must_use]
    pub fn new() -> Script {
        let mut script = Script {
            engine: Engine::new(),
            ctx: Scope::new(),
        };
        script
            .engine
            .register_fn("log_debug", |s: ImmutableString| tracing::debug!("{s}"))
            .register_fn("log_info", |s: ImmutableString| tracing::info!("{s}"))
            .register_fn("log_warn", |s: ImmutableString| tracing::warn!("{s}"))
            .register_fn("log_error", |s: ImmutableString| tracing::error!("{s}"))
            .register_fn("gen_password", |len: u32| -> String {
                Passwords::new().generate(len, 6, 2, 2)
            })
            .register_fn("gen_password_alphanum", |len: u32| -> String {
                Passwords::new().generate(len, 8, 2, 0)
            })
            .register_fn("get_env", |var: ImmutableString| -> String {
                std::env::var(var.to_string()).unwrap_or("".into())
            })
            .register_fn("base64_decode", |val: ImmutableString| -> ImmutableString {
                String::from_utf8(STANDARD.decode(val.to_string()).unwrap())
                    .unwrap()
                    .into()
            })
            .register_fn("base64_encode", |val: ImmutableString| -> ImmutableString {
                STANDARD.encode(val.to_string()).into()
            })
            .register_fn("json_encode", |val: Dynamic| -> RhaiRes<ImmutableString> {
                serde_json::to_string(&val)
                    .map_err(|e| rhai_err(Error::SerializationError(e)))
                    .map(|v| v.into())
            })
            .register_fn("json_encode_escape", |val: Dynamic| -> RhaiRes<ImmutableString> {
                let str = serde_json::to_string(&val).map_err(|e| rhai_err(Error::SerializationError(e)))?;
                Ok(format!("{:?}", str).into())
            })
            .register_fn("json_decode", |val: ImmutableString| -> RhaiRes<Dynamic> {
                serde_json::from_str(val.as_ref()).map_err(|e| rhai_err(Error::SerializationError(e)))
            })
            .register_fn("yaml_encode", |val: Dynamic| -> RhaiRes<ImmutableString> {
                serde_yaml::to_string(&val)
                    .map_err(|e| rhai_err(Error::YamlError(e)))
                    .map(|v| v.into())
            })
            .register_fn("yaml_encode", |val: Map| -> RhaiRes<ImmutableString> {
                serde_yaml::to_string(&val)
                    .map_err(|e| rhai_err(Error::YamlError(e)))
                    .map(|v| v.into())
            })
            .register_fn("yaml_decode", |val: ImmutableString| -> RhaiRes<Dynamic> {
                serde_yaml::from_str(val.as_ref()).map_err(|e| rhai_err(Error::YamlError(e)))
            })
            .register_fn(
                "yaml_decode_multi",
                |val: ImmutableString| -> RhaiRes<Vec<Dynamic>> {
                    let mut res = Vec::new();
                    if val.len() > 5 {
                        // non-empty string only
                        for document in serde_yaml::Deserializer::from_str(val.as_ref()) {
                            let doc =
                                Dynamic::deserialize(document).map_err(|e| rhai_err(Error::YamlError(e)))?;
                            res.push(doc);
                        }
                    }
                    Ok(res)
                },
            );
        script
            .engine
            .register_type_with_name::<HandleBars>("HandleBars")
            .register_fn("new_hbs", HandleBars::new)
            .register_fn("register_template", HandleBars::rhai_register_template)
            .register_fn("render_from", HandleBars::rhai_render);
        script
            .engine
            .register_type_with_name::<RestClient>("RestClient")
            .register_fn("new_client", RestClient::new)
            .register_fn("headers_reset", RestClient::headers_reset_rhai)
            .register_fn("set_baseurl", RestClient::baseurl_rhai)
            .register_fn("set_server_ca", RestClient::set_server_ca)
            .register_fn("set_mtls_cert_key", RestClient::set_mtls)
            .register_fn("add_header", RestClient::add_header_rhai)
            .register_fn("add_header_json", RestClient::add_header_json)
            .register_fn("add_header_bearer", RestClient::add_header_bearer)
            .register_fn("add_header_basic", RestClient::add_header_basic)
            .register_fn("head", RestClient::rhai_head)
            .register_fn("get", RestClient::rhai_get)
            .register_fn("delete", RestClient::rhai_delete)
            .register_fn("patch", RestClient::rhai_patch)
            .register_fn("post", RestClient::rhai_post)
            .register_fn("put", RestClient::rhai_put)
            .register_fn("http_get", RestClient::rhai_get)
            .register_fn("http_delete", RestClient::rhai_delete)
            .register_fn("http_patch", RestClient::rhai_patch)
            .register_fn("http_post", RestClient::rhai_post)
            .register_fn("http_put", RestClient::rhai_put);
        script
            .engine
            .register_type_with_name::<Argon>("Argon")
            .register_fn("new_argon", Argon::new)
            .register_fn("hash", Argon::rhai_hash);
        script.add_code("fn assert(cond, mess) {if (!cond){throw mess}}");
        script
    }

    pub fn add_code(&mut self, code: &str) {
        match self.engine.compile(code) {
            Ok(ast) => {
                match Module::eval_ast_as_new(self.ctx.clone(), &ast, &self.engine) {
                    Ok(module) => {
                        self.engine.register_global_module(module.into());
                    }
                    Err(e) => {
                        tracing::error!("Parsing {code} failed with: {e:}");
                    }
                };
            }
            Err(e) => {
                tracing::error!("Loading {code} failed with: {e:}")
            }
        };
    }

    pub fn set_dynamic(&mut self, name: &str, val: &serde_json::Value) {
        let value: Dynamic = serde_json::from_str(&serde_json::to_string(&val).unwrap()).unwrap();
        self.ctx.set_or_push(name, value);
    }

    pub fn eval(&mut self, script: &str) -> Result<serde_json::Value, Error> {
        match self.engine.eval_with_scope::<rhai::Map>(&mut self.ctx, script) {
            Ok(v) => {
                let value: serde_json::Value =
                    serde_json::from_str(&serde_json::to_string(&v).unwrap()).unwrap();
                Ok(value)
            }
            Err(e) => Err(RhaiError(e)),
        }
    }
}
