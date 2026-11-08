use cedar_benchmarks::TemplateLink;
use cedar_policy_core::validator::CoreSchema;
use cedar_policy_core::{
    ast::{Context, Entity, Request, RequestSchemaAllPass, RestrictedExpr},
    entities::{EntityJson, EntityJsonParser, TCComputation},
    extensions::Extensions,
};
use serde::{Deserialize, Serialize};
use std::{fs::File, io::BufReader, path::Path};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub format_version: u32,
    pub app: String,
    pub num_entities: usize,
    pub num_hierarchies: usize,
    pub num_requests: usize,
    pub schema_bytes: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Workload {
    entities: Vec<EntityJson>,
    links: Vec<Link>,
    requests: Vec<SavedRequest>,
}

#[derive(Deserialize, Serialize)]
struct Link {
    template_name: String,
    principal: String,
    resource: String,
}

#[derive(Deserialize, Serialize)]
struct SavedRequest {
    principal: String,
    action: String,
    resource: String,
    context: String,
}

pub fn read<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    serde_json::from_reader(BufReader::new(
        File::open(path).unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display())),
    ))
    .unwrap_or_else(|error| panic!("invalid corpus {}: {error}", path.display()))
}

pub fn write<T: Serialize>(path: &Path, value: &T) {
    serde_json::to_writer(
        File::options()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap_or_else(|error| panic!("cannot create {}: {error}", path.display())),
        value,
    )
    .expect("cannot serialize corpus");
}

impl Workload {
    pub fn capture(entities: &[Entity], links: &[TemplateLink], requests: &[Request]) -> Self {
        Self {
            entities: entities
                .iter()
                .map(|entity| EntityJson::from_entity(entity).expect("cannot save entity"))
                .collect(),
            links: links
                .iter()
                .map(|link| Link {
                    template_name: link.template_name.clone(),
                    principal: link.principal.to_string(),
                    resource: link.resource.to_string(),
                })
                .collect(),
            requests: requests
                .iter()
                .map(|request| SavedRequest {
                    principal: request
                        .principal()
                        .uid()
                        .expect("concrete principal")
                        .to_string(),
                    action: request.action().uid().expect("concrete action").to_string(),
                    resource: request
                        .resource()
                        .uid()
                        .expect("concrete resource")
                        .to_string(),
                    context: RestrictedExpr::from(
                        request.context().expect("concrete context").clone(),
                    )
                    .to_string(),
                })
                .collect(),
        }
    }

    pub fn restore(self, schema: &CoreSchema) -> (Vec<Entity>, Vec<TemplateLink>, Vec<Request>) {
        let entities = EntityJsonParser::new(
            Some(schema),
            Extensions::all_available(),
            TCComputation::AssumeAlreadyComputed,
        )
        .from_json_value(serde_json::to_value(self.entities).expect("entity JSON"))
        .expect("cannot restore corpus entities");
        let links = self
            .links
            .into_iter()
            .map(|link| TemplateLink {
                template_name: link.template_name,
                principal: link.principal.parse().expect("invalid link principal"),
                resource: link.resource.parse().expect("invalid link resource"),
            })
            .collect();
        let requests = self
            .requests
            .into_iter()
            .map(|request| {
                let context: RestrictedExpr = request.context.parse().expect("invalid context");
                Request::new(
                    (request.principal.parse().expect("invalid principal"), None),
                    (request.action.parse().expect("invalid action"), None),
                    (request.resource.parse().expect("invalid resource"), None),
                    Context::from_expr(context.as_borrowed(), Extensions::all_available())
                        .expect("cannot restore context"),
                    None::<&RequestSchemaAllPass>,
                    Extensions::all_available(),
                )
                .expect("cannot restore request")
            })
            .collect();
        (entities.iter().cloned().collect(), links, requests)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saved_request_preserves_nonempty_context_and_escaped_identifiers() {
        let request = Request::new(
            (r#"User::"a\"b""#.parse().unwrap(), None),
            (r#"Action::"read""#.parse().unwrap(), None),
            (r#"File::"f""#.parse().unwrap(), None),
            Context::from_json_str(r#"{"count":7,"nested":{"ok":true},"ids":[1,2]}"#).unwrap(),
            None::<&RequestSchemaAllPass>,
            Extensions::all_available(),
        )
        .unwrap();
        let saved = Workload::capture(&[], &[], &[request.clone()]);
        let decoded: Workload =
            serde_json::from_slice(&serde_json::to_vec(&saved).unwrap()).unwrap();
        let saved_request = &decoded.requests[0];
        let context: RestrictedExpr = saved_request.context.parse().unwrap();
        assert_eq!(
            Context::from_expr(context.as_borrowed(), Extensions::all_available()).unwrap(),
            *request.context().unwrap()
        );
        assert_eq!(
            saved_request
                .principal
                .parse::<cedar_policy_core::ast::EntityUID>()
                .unwrap(),
            *request.principal().uid().unwrap()
        );
    }
}
