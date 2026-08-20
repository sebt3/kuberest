use crate::passwordhandler::Passwords;
use handlebars::handlebars_helper;
pub use vynil_core::hbs::HandleBars;

// kuberest's `password_generator` CRD field is weight-based (weight_alphas/weight_numbers/weight_symbols),
// unlike vynil-core's minimum-count based `gen_password`. Re-registered here to keep template behavior
// unchanged for existing RestEndPoint templates.
handlebars_helper!(gen_password: |len:u32| Passwords::new().generate(len, 6, 2, 2));
handlebars_helper!(gen_password_alphanum:  |len:u32| Passwords::new().generate(len, 8, 2, 0));

#[must_use]
pub fn new_hbs() -> HandleBars<'static> {
    let mut hbs = HandleBars::new();
    hbs.engine_mut()
        .register_helper("gen_password", Box::new(gen_password));
    hbs.engine_mut()
        .register_helper("gen_password_alphanum", Box::new(gen_password_alphanum));
    hbs
}
