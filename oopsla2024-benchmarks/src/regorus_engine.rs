use std::time::Duration;

use crate::entity_graph::EntityGraph;
use crate::rego_requests::gdrive;
use crate::rego_requests::github::{GithubOpaInput, GithubRequest};
use crate::tinytodo_generator::{
    cedar::Request as TinyTodoCedarRequest, entities::Entities as TinyTodoGeneratedEntities,
    opa::to_opa,
};
use crate::ExampleApp;
use crate::SingleExecutionReport;
use cedar_policy_core::ast::Request;
use cedar_policy_core::authorizer::Decision;
use cedar_policy_core::entities::NoEntitiesSchema;
use cedar_policy_core::extensions::Extensions;
use log::warn;
use serde::Deserialize;

use regorus::{Engine, Value};

pub struct RegorusEngine<'a, T>
where
    T: EntityGraph,
{
    /// app object
    app: &'a ExampleApp,
    /// entity data
    entities: T,
}

impl<'a, T: EntityGraph> RegorusEngine<'a, T> {
    pub fn new(
        app: &'a ExampleApp,
        entities: impl IntoIterator<Item = &'a cedar_policy_core::ast::Entity>,
    ) -> Self {
        Self {
            app,
            entities: T::from_iter(entities),
        }
    }

    pub fn execute(&self, requests: Vec<Request>) -> impl Iterator<Item = SingleExecutionReport> {
        match self.app.name {
            "tinytodo" => {
                let requests: Vec<_> = requests
                    .into_iter()
                    .map(TinyTodoCedarRequest::from)
                    .collect();
                let entities = TinyTodoGeneratedEntities::from_cedar_entities(self.entities.iter());
                let opa_json_payload =
                    serde_json::to_string(&to_opa(&entities, &requests)).unwrap();
                run_rego_requests(opa_json_payload)
            }
            "github" => {
                let requests: Vec<_> = requests
                    .iter()
                    .map(|r| GithubRequest::new(r, &self.entities))
                    .collect();
                let json_payload = serde_json::to_string(&GithubOpaInput::new(requests)).unwrap();
                run_rego_requests(json_payload)
            }
            "gdrive" => {
                let closed = cedar_policy_core::entities::Entities::from_entities(
                    self.entities.iter(),
                    None::<&NoEntitiesSchema>,
                    cedar_policy_core::entities::TCComputation::ComputeNow,
                    Extensions::all_available(),
                )
                .unwrap();
                let requests: Vec<_> = requests
                    .iter()
                    .map(|r| gdrive::Request::new(r, &self.entities, &closed))
                    .collect();
                let json_payload = serde_json::to_string(&gdrive::Input::new(requests)).unwrap();
                run_rego_requests(json_payload)
            }
            appname => {
                warn!("Regorus engine for {appname} is not yet implemented; not collecting data for Rego with {appname}");
                run_rego_requests("[]".to_string())
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct GoTestOutput {
    #[serde(rename = "Decision")]
    decision: bool,
    #[serde(rename = "Dur")]
    dur_nanoseconds: u64,
}

impl From<GoTestOutput> for SingleExecutionReport {
    fn from(val: GoTestOutput) -> Self {
        let decision = if val.decision {
            Decision::Allow
        } else {
            Decision::Deny
        };
        SingleExecutionReport {
            dur: Duration::from_nanos(val.dur_nanoseconds),
            decision,
            errors: vec![],
            context_attrs: 0,
        }
    }
}

/// If requests is the empty list `[]`, then no requests will be run, and the
/// returned iterator will be empty
pub fn run_rego_requests(payload: String) -> impl Iterator<Item = SingleExecutionReport> {
    let payload = Value::from_json_str(&payload).unwrap();
    let mut engine = Engine::new();

    let mut test_outputs = vec![];

    if payload["Policy"].as_string().is_ok() {
        engine
            .add_policy(
                "policy.rego".to_string(),
                payload["Policy"].as_string().unwrap().to_string(),
            )
            .unwrap();

	let namespace = payload["Namespace"].as_string().unwrap().to_string();
        let query = format!(
            "data.{}.allow",
            namespace
        );

        for (idx, req) in payload["Requests"].as_array().unwrap().iter().enumerate() {
            let query = query.clone();

	    if idx == 0 {
		engine.clear_data();
		engine.set_input(req.clone());
		let data = engine.eval_rule(format!("data.{}.preprocess", namespace)).unwrap();
		engine.add_data(data).unwrap();
	    }
	    
            let start_time = std::time::Instant::now();
            engine.set_input(req.clone());
            let decision = engine.eval_rule(query).unwrap() == Value::Bool(true);
            let dur_nanoseconds = start_time.elapsed().as_nanos() as u64;

            test_outputs.push(GoTestOutput {
                decision,
                dur_nanoseconds,
            });
        }
    }

    test_outputs.into_iter().map(|result| result.into())
}
