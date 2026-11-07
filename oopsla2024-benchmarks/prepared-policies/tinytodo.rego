package tinytodo
import future.keywords

preprocess := {
    "ancestors": {principal: graph.reachable(input.Data.Groups, [principal]) |
        some principal, _ in input.Data.Groups
    },
    "public_actions": {"Action::\"CreateList\"", "Action::\"GetLists\""},
    "permissions": {
        "Action::\"GetList\"": ["Readers", "Writers"],
        "Action::\"UpdateList\"": ["Writers"],
        "Action::\"CreateTask\"": ["Writers"],
        "Action::\"UpdateTask\"": ["Writers"],
        "Action::\"DeleteTask\"": ["Writers"],
    },
}

allow = true {
    input.Request.Action in data.public_actions
}

allow = true {
    input.Request.Resource.Owner == input.Request.Principal
}

allow = true {
    some attribute in data.permissions[input.Request.Action]
    input.Request.Principal in input.Request.Resource[attribute]
}

allow = true {
    some attribute in data.permissions[input.Request.Action]
    some group in input.Request.Resource[attribute]
    group in data.ancestors[input.Request.Principal]
}
