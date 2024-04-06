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


## We are authorized if any of the applicable actions are allowed
allow {
      # What capabilities does principal have?
      capabilities := data.capabilities[input.principal]

      # For each action and associated capability in the resource
      some action, cap in input.resource

      # Does principal have the capability?
      cap in capabilities

      # Is the action applicable?
      action in data.applicable[input.action]
} else {
      # What capabilities does principal have?
      capabilities := data.capabilities[input.principal]

      # For each action and associated capability in the resource's owner
      some action, cap in input.resource.owner

      # Does principal have the capability?
      cap in capabilities

      # Is the action applicable?
      action in data.applicable[input.action]
} 
