# kuberest — guide projet

Contexte projet partagé pour tout agent (Claude Code, opencode/Qwen, etc.).
Personnel uniquement, jamais professionnel.

## Ce qu'est kuberest

Opérateur Kubernetes en Rust qui crée/met à jour/supprime des objets REST sur
des api-endpoints RESTful, piloté par une Custom Resource. L'objectif : ne plus
jamais écrire de Job post-install rempli de `curl` pour configurer une appli
après son déploiement (provisioning OpenID, forges, Harbor, etc.).

Inspirations : le provider Terraform `Mastercard/restapi` et Tekton.

- **CRD** : `RestEndPoint` — groupe `kuberest.solidite.fr`, pluriel
  `restendpoints`, nom court `rep`.
- **Licence** : Apache-2.0. **Édition Rust** : 2024.
- **Doc publiée** : https://sebt3.github.io/kuberest/docs/

## Architecture

Binaires (`Cargo.toml`) :
- `controller` (`src/main.rs`) — l'opérateur, binaire par défaut.
- `crdgen` (`src/crdgen.rs`) — génère le YAML de la CRD depuis les types Rust.
- `dummy` — placeholder de build.
- lib `controller` (`src/lib.rs`) — expose `Error`/`Result`, les macros
  `template!`/`update!`/`create!`, et re-exporte `restendpoint`.

Modules `src/` (les gros en premier) :
- `restendpoint.rs` — cœur : reconcile / cleanup (teardown) / helpers.
- `httphandler.rs` — `RestClient` ; pattern en couches
  `http_*` (brut) → `body_*` (gestion d'erreur) → `json_*` (JSON) → `rhai_*` (exposé à Rhai).
- `types.rs` — structs/enums de la CRD.
- `k8shandlers.rs` — accès secrets/configmaps/objets K8s.
- `rhaihandler.rs` — moteur de scripting Rhai.
- `handlebarshandler.rs` — templating Handlebars.
- `passwordhandler.rs` / `hasheshandlers.rs` — argon2, bcrypt, hashes.
- `metrics.rs`, `telemetry.rs`, `state.rs` (Context/Diagnostics/State).
- `fixtures.rs` — fixtures de test (`#[cfg(test)]`).

Templating : un `RestEndPoint` enchaîne des inputs (secrets/configmaps/templates),
des read/write groups vers les APIs REST, et des outputs (secrets/configmaps).
Les valeurs circulent via Handlebars **et** Rhai.

## Multi-tenant

Par défaut l'opérateur est limité au tenant courant (refuse de lire des secrets
hors namespaces partageant le label de tenant). `MULTI_TENANT=false` pour un
comportement global ; `TENANT_LABEL` choisit le label commun.
(Chart : `tenants.enabled`, `tenants.label`.)

## Build, test, lint

> `cargo` peut ne pas être dans le PATH selon l'environnement : utiliser
> `~/.cargo/bin/cargo` le cas échéant.

```sh
cargo build
cargo test                              # tests unitaires
cargo test --lib --all -- --ignored     # tests d'intégration (nécessite un cluster k3d)
cargo +nightly fmt -- --check           # format (nightly requis)
cargo clippy --all-features
```

## Génération de code — à ne PAS oublier

Le projet utilise `cargo-commander`. Après toute modification des types de la CRD
ou du chart, régénérer les artefacts commités, sinon la CI échoue :

```sh
cargo cmd generate     # met à jour Chart.yaml (appVersion/version),
                       # deploy/crd/crd.yaml et deploy/operator/deployment.yaml
```

La CI (job `unit`) fait `git diff --exit-code deploy/` : tout artefact non
régénéré et commité casse le build. `cargo cmd precommit` enchaîne
`cargo update` + `clippy --fix` + `generate` + `fmt`.

## Conventions & pièges

- Quand un champ migre vers un autre module, il doit devenir `pub`.
- `use tracing::*` entre en conflit avec la struct `Metadata` — imports explicites.
- kube v2 : `Recorder::new(client, reporter)` (2 args) ;
  `publish(&Event, &ObjectReference)`.
- prometheus 0.14 : `.as_str()` (pas `.as_ref()`) pour les valeurs de label.
- Versions clés : kube 2.0.1, k8s-openapi 0.26, reqwest 0.12, rhai 1.20,
  handlebars 6.2, serde_yaml 0.9.

## Git / commits

- **Pas de `Co-Authored-By`** dans les messages de commit.
- **Pas de prénoms ni d'identifiants personnels** dans les fichiers commités
  (même logique qu'un token : termes génériques uniquement).
- Brancher avant de committer si on est sur `main`. Committer/pousser
  uniquement sur demande explicite.

## Doute sur l'usage métier ?

L'auteur du projet est disponible : en cas de doute sur le comportement attendu
de kuberest, **demander** plutôt que de deviner seul.
