package github
import future.keywords


################################################################################
#### Github Rego Policy
#### input -> dict:
####   principal -> string
####   action -> string
####   resource -> dict:
####     readers -> string
####     writers -> string
####     admins -> string
####     triagers -> string
####     maintainers -> string
####     owner -> dict:
####     	readers -> string
####     	writers -> string
####     	admins -> string
####   orgs -> dict (Org-Graph)
################################################################################



#principal := "user::E"
#action := "write"

#org_chart := {
#    "RepoPermission::RepoF write" : [],
#	"team::B" : ["RepoPermission::RepoF write"],
#    "user::E" : ["team::B"]
#}
#
#org := {
#	"read" : "RepoPermission::RepoF read",
#	"triage" : "RepoPermission::RepoF triage",
#	"write" : "RepoPermission::RepoF write",
#	"maintain" : "RepoPermission::RepoF maintain",
#	"admin" : "RepoPermission::RepoF admin",
#}


actions = {
	"Action::\"read\"": ["Action::\"triage\"", "Action::\"write\"", "Action::\"maintain\"", "Action::\"admin\""],
	"Action::\"triage\"": ["Action::\"write\"", "Action::\"maintain\"", "Action::\"admin\""],
	"Action::\"write\"": ["Action::\"maintain\"", "Action::\"admin\""],
	"Action::\"maintain\"": ["Action::\"admin\""],
	"Action::\"admin\"": [],
}


preprocess := {
  ## Look up applicable actions (ex: 'write' -> 'read', 'triage', 'write')
  "applicable" : { action : reachable |
     some action,_ in actions;
     reachable := graph.reachable(actions, [action])
   },
   "capabilities": { principal : capabilities |
     some principal,_ in input.orgs
     capabilities := graph.reachable(input.orgs, [principal])
   }
}

## Can a specific action be performed
can_perform(action) {
	## Look up the repo's object capability for this action
	cap := input.resource[action]

	## Can we reach that capability in the org chart?
	cap in data.capabilities[input.principal] # graph.reachable(input.orgs, [input.principal])
}

#can_perform[action] = true  {
else {
	## Do the same thing, but user the owner's object capability
	cap := input.resource.owner[action]

	## Can we reach that capability in the org chart?
	cap in data.capabilities[input.principal] # graph.reachable(input.orgs, [input.principal])
}



## We are authorized if any of the applicable actions are allowed
allow {
	action := data.applicable[input.action][_]
	can_perform(action)
}


