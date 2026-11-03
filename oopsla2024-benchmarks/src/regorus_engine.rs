use crate::entity_graph::EntityGraph;
use crate::rego_engine::request_payload;
use crate::{ExampleApp, SingleExecutionReport};
use cedar_policy_core::{ast::Request, authorizer::Decision};
use regorus::languages::rego::compiler::Compiler;
use regorus::rvm::vm::RegoVM;
use regorus::{Engine, Rc, Value};
use std::time::Instant;

#[derive(Clone, Copy, Debug)]
pub enum RegorusBackend {
    Interpreter,
    Rvm,
}

pub struct RegorusEngine<'a, T: EntityGraph> {
    app: &'a ExampleApp,
    entities: T,
    backend: RegorusBackend,
}

impl<'a, T: EntityGraph> RegorusEngine<'a, T> {
    pub fn new(
        app: &'a ExampleApp,
        entities: impl IntoIterator<Item = &'a cedar_policy_core::ast::Entity>,
        backend: RegorusBackend,
    ) -> Self {
        assert!(
            matches!(app.name, "github" | "gdrive" | "tinytodo"),
            "Regorus does not support {}",
            app.name
        );
        Self {
            app,
            entities: T::from_iter(entities),
            backend,
        }
    }

    pub fn execute(&self, requests: Vec<Request>) -> impl Iterator<Item = SingleExecutionReport> {
        let mut payload = request_payload(self.app, &self.entities, requests);
        let optimized_policy = match self.app.name {
            "github" => Some(include_str!("../benches/github/rego/github_regorus.rego")),
            "gdrive" => Some(include_str!("../benches/gdrive/rego/gdrive_regorus.rego")),
            "tinytodo" => Some(include_str!(
                "../benches/tinytodo/rego/tinytodo_regorus.rego"
            )),
            _ => None,
        };
        if let Some(policy) = optimized_policy {
            payload["Policy"] = policy.into();
        }
        run_requests(payload, self.backend).into_iter()
    }
}

fn decision(value: Value) -> Decision {
    match value {
        Value::Bool(true) => Decision::Allow,
        Value::Bool(false) | Value::Undefined => Decision::Deny,
        value => panic!("expected boolean authorization result, got {value:?}"),
    }
}

fn run_requests(payload: serde_json::Value, backend: RegorusBackend) -> Vec<SingleExecutionReport> {
    let preparation = if payload["Namespace"] == "gdrive" {
        let requests = payload["Requests"].as_array().expect("missing requests");
        Some(serde_json::json!({
            "files": requests.first().map(|request| &request["files"]),
            "principals": payload["Principals"].as_array().expect("missing principal population"),
        }))
    } else {
        None
    };
    let payload = Value::from_json_str(&payload.to_string()).expect("invalid request payload");
    let requests = payload["Requests"].as_array().expect("missing requests");
    let Some(first) = requests.first() else {
        return vec![];
    };
    let namespace = payload["Namespace"].as_string().expect("missing namespace");
    let query: Rc<str> = format!("data.{namespace}.allow").into();
    let mut engine = Engine::new();
    engine.set_rego_v0(true);
    engine
        .add_policy(
            "policy.rego".into(),
            payload["Policy"]
                .as_string()
                .expect("missing policy")
                .to_string(),
        )
        .expect("failed to parse Rego policy");
    engine.set_input(match preparation {
        Some(preparation) => {
            Value::from_json_str(&preparation.to_string()).expect("invalid preprocessing input")
        }
        None => first.clone(),
    });
    let preprocessing_start = Instant::now();
    if matches!(namespace.as_ref(), "github" | "gdrive" | "tinytodo") {
        let data = engine
            .eval_rule(format!("data.{namespace}.preprocess"))
            .expect("entity graph preprocessing failed");
        engine
            .add_data(data)
            .expect("failed to load preprocessed data");
    }
    let preprocessing_dur = preprocessing_start.elapsed();

    match backend {
        RegorusBackend::Interpreter => {
            engine.set_input(first.clone());
            engine
                .eval_rule(query.to_string())
                .expect("interpreter warm-up failed");
            requests
                .iter()
                .map(|request| {
                    let start = Instant::now();
                    engine.set_input(request.clone());
                    let result = engine
                        .eval_rule(query.to_string())
                        .expect("Rego evaluation failed");
                    SingleExecutionReport {
                        dur: start.elapsed(),
                        decision: decision(result),
                        errors: vec![],
                        context_attrs: 0,
                    }
                })
                .collect()
        }
        RegorusBackend::Rvm => {
            let compilation_start = Instant::now();
            let policy = engine
                .compile_with_entrypoint(&query)
                .expect("failed to compile Rego policy");
            let program = Compiler::compile_from_policy(&policy, &[query.as_ref()])
                .expect("failed to compile RVM program");
            let mut vm = RegoVM::new();
            vm.load_program(program);
            vm.set_data(engine.get_data())
                .expect("failed to load RVM data");
            let compilation_dur = compilation_start.elapsed();
            log::info!(
                "regorus_setup app={} backend=Rvm preprocessing_us={:.3} compilation_us={:.3}",
                namespace,
                preprocessing_dur.as_secs_f64() * 1_000_000.0,
                compilation_dur.as_secs_f64() * 1_000_000.0,
            );
            vm.set_input(first.clone());
            vm.execute().expect("RVM warm-up failed");
            requests
                .iter()
                .map(|request| {
                    let start = Instant::now();
                    vm.set_input(request.clone());
                    let result = vm.execute().expect("RVM evaluation failed");
                    SingleExecutionReport {
                        dur: start.elapsed(),
                        decision: decision(result),
                        errors: vec![],
                        context_attrs: 0,
                    }
                })
                .collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn assert_matches_original_policy(payload: serde_json::Value, policy: &str) {
        let namespace = payload["Namespace"].as_str().unwrap();
        let mut original = Engine::new();
        original.set_rego_v0(true);
        original
            .add_policy("original.rego".into(), policy.into())
            .unwrap();
        let expected: Vec<_> = payload["Requests"]
            .as_array()
            .unwrap()
            .iter()
            .map(|request| {
                original.set_input(Value::from_json_str(&request.to_string()).unwrap());
                decision(
                    original
                        .eval_rule(format!("data.{namespace}.allow"))
                        .unwrap(),
                )
            })
            .collect();
        assert!(expected.contains(&Decision::Allow));
        assert!(expected.contains(&Decision::Deny));
        for backend in [RegorusBackend::Interpreter, RegorusBackend::Rvm] {
            let actual: Vec<_> = run_requests(payload.clone(), backend)
                .into_iter()
                .map(|report| report.decision)
                .collect();
            assert_eq!(actual, expected, "{backend:?}");
        }
    }

    #[test]
    fn interpreter_and_rvm_reset_between_allow_deny_and_undefined() {
        let payload = json!({
            "Policy": "package test\nallow = input.allowed { input.present }",
            "Namespace": "test",
            "Requests": [
                {"present": true, "allowed": true},
                {"present": true, "allowed": false},
                {"present": false, "allowed": true},
                {"present": true, "allowed": true}
            ]
        });
        for backend in [RegorusBackend::Interpreter, RegorusBackend::Rvm] {
            let decisions: Vec<_> = run_requests(payload.clone(), backend)
                .into_iter()
                .map(|report| report.decision)
                .collect();
            assert_eq!(
                decisions,
                [
                    Decision::Allow,
                    Decision::Deny,
                    Decision::Deny,
                    Decision::Allow
                ]
            );
        }
    }

    #[test]
    fn preprocessing_is_available_in_both_backends() {
        let payload = json!({
            "Policy": "package github\nimport future.keywords.in\npreprocess := {\"allowed\": input.users}\nallow { input.user in data.allowed }",
            "Namespace": "github",
            "Requests": [
                {"users": ["alice"], "user": "alice"},
                {"user": "bob"},
                {"user": "alice"}
            ]
        });
        for backend in [RegorusBackend::Interpreter, RegorusBackend::Rvm] {
            let decisions: Vec<_> = run_requests(payload.clone(), backend)
                .into_iter()
                .map(|report| report.decision)
                .collect();
            assert_eq!(
                decisions,
                [Decision::Allow, Decision::Deny, Decision::Allow]
            );
        }
    }

    #[test]
    fn github_owner_capability_is_allowed() {
        let payload = json!({
            "Policy": include_str!("../benches/github/rego/github_regorus.rego"),
            "Namespace": "github",
            "Requests": [{
                "principal": "User::\"alice\"",
                "action": "Action::\"read\"",
                "orgs": {"User::\"alice\"": ["org-writers"], "org-writers": []},
                "resource": {
                    "Action::\"read\"": "repo-readers",
                    "Action::\"write\"": "repo-writers",
                    "owner": {
                        "Action::\"read\"": "org-readers",
                        "Action::\"write\"": "org-writers"
                    }
                }
            }]
        });
        for backend in [RegorusBackend::Interpreter, RegorusBackend::Rvm] {
            assert_eq!(
                run_requests(payload.clone(), backend)[0].decision,
                Decision::Allow
            );
        }
    }

    #[test]
    fn tinytodo_transitive_read_and_write_permissions() {
        let payload = json!({
            "Policy": include_str!("../benches/tinytodo/rego/tinytodo_regorus.rego"),
            "Namespace": "tinytodo",
            "Requests": [
                {
                    "Data": {"Groups": {"alice": ["team"], "team": ["readers", "writers"], "readers": [], "writers": [], "mallory": []}},
                    "Request": {
                        "Principal": "alice", "Action": "Action::\"GetList\"",
                        "Resource": {"Owner": "bob", "Readers": ["readers"], "Writers": []}
                    }
                },
                {
                    "Data": {"Groups": {"alice": ["team"], "team": ["readers", "writers"], "readers": [], "writers": [], "mallory": []}},
                    "Request": {
                        "Principal": "alice", "Action": "Action::\"UpdateList\"",
                        "Resource": {"Owner": "bob", "Readers": [], "Writers": ["writers"]}
                    }
                },
                {
                    "Data": {"Groups": {"alice": ["team"], "team": ["readers", "writers"], "readers": [], "writers": [], "mallory": []}},
                    "Request": {
                        "Principal": "mallory", "Action": "Action::\"GetList\"",
                        "Resource": {"Owner": "bob", "Readers": [], "Writers": []}
                    }
                }
            ]
        });
        for backend in [RegorusBackend::Interpreter, RegorusBackend::Rvm] {
            let decisions: Vec<_> = run_requests(payload.clone(), backend)
                .into_iter()
                .map(|report| report.decision)
                .collect();
            assert_eq!(
                decisions,
                [Decision::Allow, Decision::Allow, Decision::Deny],
                "{backend:?}"
            );
        }
    }

    #[test]
    fn prepared_gdrive_matches_original_policy_for_every_action() {
        let files = json!({
            "document": ["folder"], "folder": [], "owned-document": [],
            "view-root": ["view-document"], "view-document": [],
            "public-document": [], "unrelated": []
        });
        let principals = [
            json!({"uid": "alice", "documentsAndFoldersWithViewAccess": ["view-root"],
                "ownedDocuments": ["owned-document"], "ownedFolders": ["folder"]}),
            json!({"uid": "bob", "documentsAndFoldersWithViewAccess": [],
                "ownedDocuments": [], "ownedFolders": []}),
        ];
        let mut requests = Vec::new();
        for principal in &principals {
            for action in ["read", "write", "share", "changeOwner", "createDocument"] {
                for resource in [
                    "document",
                    "folder",
                    "owned-document",
                    "view-document",
                    "public-document",
                    "unrelated",
                ] {
                    requests.push(json!({
                        "principal": principal,
                        "action": format!("Action::\"{action}\""),
                        "resource": {"uid": resource, "isPublic": resource == "public-document"},
                        "files": files,
                    }));
                }
            }
        }
        let payload = json!({
            "Policy": include_str!("../benches/gdrive/rego/gdrive_regorus.rego"),
            "Namespace": "gdrive", "Requests": requests, "Principals": principals
        });
        assert_matches_original_policy(payload, include_str!("../benches/gdrive/rego/gdrive.rego"));
    }

    #[test]
    fn gdrive_generated_views_and_converted_permissions_match_cedar() {
        use crate::entity_graph::OpenEntities;
        use cedar_policy_core::ast::{Context, RequestSchemaAllPass};
        use cedar_policy_core::entities::{EntityJsonParser, TCComputation};
        use cedar_policy_core::extensions::Extensions;
        use cedar_policy_core::validator::CoreSchema;

        let output = std::process::Command::new("python3")
            .args([
                "generators/gdrive_entity_generator.py",
                "2",
                "1",
                "1",
                "1",
                "1",
            ])
            .output()
            .unwrap();
        assert!(output.status.success());
        let generated: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let uids: std::collections::HashSet<_> = generated
            .as_array()
            .unwrap()
            .iter()
            .map(|entity| entity["uid"].to_string())
            .collect();
        for entity in generated.as_array().unwrap() {
            for parent in entity["parents"].as_array().unwrap() {
                assert!(
                    uids.contains(&parent.to_string()),
                    "nonexistent parent: {parent}"
                );
            }
        }

        let mut u = arbitrary::Unstructured::new(&[0; 8192]);
        let app = ExampleApp::gdrive(&mut u);
        let validator_schema = app.validator_schema();
        let schema = CoreSchema::new(&validator_schema);
        let user_view = json!({"__entity": {"type": "View", "id": "User user_0"}});
        let group_view = json!({"__entity": {"type": "View", "id": "Group group_0"}});
        let folder = json!({"__entity": {"type": "Folder", "id": "folder_0"}});
        for (case, expected_read) in [
            ("direct", Decision::Allow),
            ("group", Decision::Allow),
            ("folder", Decision::Allow),
            ("none", Decision::Deny),
        ] {
            let mut entities = generated.clone();
            for entity in entities.as_array_mut().unwrap() {
                match entity["uid"]["__entity"]["type"].as_str().unwrap() {
                    "User" => {
                        entity["attrs"]["ownedDocuments"] = json!([]);
                        entity["attrs"]["ownedFolders"] = json!([]);
                    }
                    "Document" => {
                        entity["attrs"]["isPublic"] = json!(false);
                        entity["parents"] = match case {
                            "direct" => json!([user_view]),
                            "group" => json!([group_view]),
                            "folder" => json!([folder]),
                            _ => json!([]),
                        };
                    }
                    "Folder" => {
                        entity["parents"] = if case == "folder" {
                            json!([group_view])
                        } else {
                            json!([])
                        };
                    }
                    _ => {}
                }
            }
            let entities: Vec<_> = EntityJsonParser::new(
                Some(&schema),
                Extensions::all_available(),
                TCComputation::ComputeNow,
            )
            .from_json_value(entities)
            .unwrap()
            .into_iter()
            .collect();
            let requests: Vec<_> = ["read", "write"]
                .into_iter()
                .map(|action| {
                    Request::new(
                        ("User::\"user_0\"".parse().unwrap(), None),
                        (format!("Action::\"{action}\"").parse().unwrap(), None),
                        ("Document::\"doc_0\"".parse().unwrap(), None),
                        Context::empty(),
                        None::<&RequestSchemaAllPass>,
                        Extensions::all_available(),
                    )
                    .unwrap()
                })
                .collect();
            let cedar = crate::CedarEngine::new(&entities, &[], &app);
            let expected: Vec<_> = requests
                .iter()
                .map(|request| {
                    let report = cedar.execute(request.clone());
                    assert!(report.errors.is_empty());
                    report.decision
                })
                .collect();
            assert_eq!(expected, [expected_read, Decision::Deny], "{case}");
            let graph = OpenEntities::from_iter(&entities);
            let mut payload = request_payload(&app, &graph, requests);
            assert_eq!(payload["Principals"].as_array().unwrap().len(), 2);
            let mut original = Engine::new();
            original.set_rego_v0(true);
            original
                .add_policy(
                    "original.rego".into(),
                    payload["Policy"].as_str().unwrap().into(),
                )
                .unwrap();
            let original_decisions: Vec<_> = payload["Requests"]
                .as_array()
                .unwrap()
                .iter()
                .map(|request| {
                    original.set_input(Value::from_json_str(&request.to_string()).unwrap());
                    decision(original.eval_rule("data.gdrive.allow".into()).unwrap())
                })
                .collect();
            assert_eq!(original_decisions, expected, "{case} original policy");
            payload["Policy"] = include_str!("../benches/gdrive/rego/gdrive_regorus.rego").into();
            for backend in [RegorusBackend::Interpreter, RegorusBackend::Rvm] {
                let actual: Vec<_> = run_requests(payload.clone(), backend)
                    .into_iter()
                    .map(|report| report.decision)
                    .collect();
                assert_eq!(actual, expected, "{case} {backend:?}");
            }
        }
    }

    #[test]
    fn prepared_tinytodo_matches_original_for_direct_and_inherited_permissions() {
        let groups = json!({
            "alice": ["team1"],
            "team1": ["team2"], "team2": ["team1", "readers", "writers"],
            "readers": [], "writers": []
        });
        let resources = [
            json!({"Owner": "alice", "Readers": [], "Writers": []}),
            json!({"Owner": "bob", "Readers": ["alice"], "Writers": []}),
            json!({"Owner": "bob", "Readers": ["readers"], "Writers": []}),
            json!({"Owner": "bob", "Readers": [], "Writers": ["writers"]}),
            json!({"Owner": "bob", "Readers": ["mallory"], "Writers": []}),
            json!({"Owner": "bob", "Readers": [], "Writers": ["mallory"]}),
            json!({"Owner": "bob", "Readers": [], "Writers": []}),
        ];
        let mut requests = Vec::new();
        for principal in ["alice", "mallory"] {
            for action in [
                "CreateList",
                "GetLists",
                "GetList",
                "UpdateList",
                "CreateTask",
                "UpdateTask",
                "DeleteTask",
                "DeleteList",
                "EditShares",
            ] {
                for resource in &resources {
                    requests.push(json!({
                        "Data": {"Groups": groups},
                        "Request": {"Principal": principal,
                            "Action": format!("Action::\"{action}\""), "Resource": resource},
                    }));
                }
            }
        }
        assert_matches_original_policy(
            json!({
                "Policy": include_str!("../benches/tinytodo/rego/tinytodo_regorus.rego"),
                "Namespace": "tinytodo", "Requests": requests
            }),
            include_str!("../benches/tinytodo/rego/tinytodo.rego"),
        );
    }
}
