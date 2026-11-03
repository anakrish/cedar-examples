package github
import future.keywords

actions = {
    "Action::\"read\"": ["Action::\"triage\"", "Action::\"write\"", "Action::\"maintain\"", "Action::\"admin\""],
    "Action::\"triage\"": ["Action::\"write\"", "Action::\"maintain\"", "Action::\"admin\""],
    "Action::\"write\"": ["Action::\"maintain\"", "Action::\"admin\""],
    "Action::\"maintain\"": ["Action::\"admin\""],
    "Action::\"admin\"": [],
}

preprocess := {
    "applicable": {action: reachable |
        some action, _ in actions
        reachable := graph.reachable(actions, [action])
    },
    "capabilities": {principal: capabilities |
        some principal, _ in input.orgs
        capabilities := graph.reachable(input.orgs, [principal])
    },
}

allow {
    capabilities := data.capabilities[input.principal]
    some action in data.applicable[input.action]
    some resource in [input.resource, input.resource.owner]
    resource[action] in capabilities
}
