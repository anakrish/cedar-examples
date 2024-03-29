package tinytodo
import future.keywords.in

################################################################################
###### Group/Graph Management
################################################################################
#groups contains group if {
#   some user in input.data.groups[group].users
#   user == input.request.principal
# }

#groups contains group if {
#   some sub_group in groups
#   sub_group.parents[_] = group
#}


################################################################################
###### Static Action Data
################################################################################

public_actions := ["Action::\"CreateList\"", "Action::\"GetLists\""]
read_actions := ["Action::\"GetList\""]
write_actions := ["Action::\"UpdateList\"", "Action::\"CreateTask\"", "Action::\"UpdateTask\"", "Action::\"DeleteTask\""]



################################################################################
###### Read/Write rules
################################################################################
reachable := graph.reachable(input.Data.Groups, [input.Request.Principal])

# Check if we we're allowed to write
allow_write = true
# We can write if we are directly in the writers list
{
    input.Request.Principal in input.Request.Resource.Writers
}
# Or if we are transitivly in a group in the writers list
else {
    some group in input.Request.Resource.Writers
    group in reachable
}

# Check if we we're allowed to read
allow_read = true
# We can read if we are directly in the readers list
{
    input.Request.Principal in input.Request.Resource.Readers
}
# Or if we are transitivly in a group in the readers list
else {
    some group in input.Request.Resource.Readers
    group in reachable
}
# Or if we are allowed to write
else {
    allow_write
}


################################################################################
###### Toplevel rules
################################################################################


# This tracks if the query is explicitly authorized

# This tracks policy violations
default violations = set()


#blocked := true {
    #input.request.action == "Action::CreateList"
    #permissions["interns"][_] = input.request.principal
#}

# Any user can take public actions
allow = true {
    input.Request.Action in public_actions
}

# Any user can take actions on resources they own
# allow = true {
else {
    input.Request.Resource.Owner == input.Request.Principal
}


# Read actions are allowed if the user can read
# allow = true {
else {
    input.Request.Action in read_actions
    allow_read
}

# Write actions are allowed if the user can write
# allow = true {
else {
    input.Request.Action in write_actions
    allow_write
}

