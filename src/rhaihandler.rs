use rhai::{Engine, Scope, Module, ImmutableString};
use crate::{Error::*,Error};

#[derive(Debug)]
pub struct Script {
    pub engine: Engine,
    ctx: Scope<'static>
}

impl Script {
    #[must_use] pub fn new() -> Script {
        Script {
            engine: Engine::new(),
            ctx: Scope::new()
        }
    }
    pub fn extended() -> Script {
        let mut script = Self::new();
        script.engine.register_fn("log_debug", |s:ImmutableString| tracing::debug!("{s}"));
        script.engine.register_fn("log_info", |s:ImmutableString| tracing::info!("{s}"));
        script.engine.register_fn("log_warn", |s:ImmutableString| tracing::warn!("{s}"));
        script.engine.register_fn("log_error", |s:ImmutableString| tracing::error!("{s}"));
        script.add_code("fn assert(cond, mess) {if (!cond){throw mess}}");
        script
    }

    pub fn push_constant(&mut self, name:&str, val: &serde_json::Value) {
        self.ctx.push_constant(name, val.clone());
    }

    pub fn add_code(&mut self, code: &str) {
        match self.engine.compile(code) {Ok(ast) => {
            match Module::eval_ast_as_new(self.ctx.clone(), &ast,&self.engine) {Ok(module) => {
                self.engine.register_global_module(module.into());
            }, Err(e) => {tracing::error!("Parsing {code} failed with: {e:}");},};
        }, Err(e) => {tracing::error!("Loading {code} failed with: {e:}")},};
    }
    pub fn eval(&mut self, script: &str) -> Result<serde_json::Value, Error> {
        match self.engine.eval_with_scope::<serde_json::Value>(&mut self.ctx, script) {
            Ok(v) => Ok(v),
            Err(e) => Err(RhaiError(e))
        }
    }
}
