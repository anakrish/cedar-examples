package gdrive
import future.keywords

children := {parent: {child |
    some child, parents in input.files
    parent in parents
} | some parent, _ in input.files}

preprocess := {
    "capabilities": {principal.uid: {
        "view": graph.reachable(input.files, principal.documentsAndFoldersWithViewAccess),
        "ownedDocuments": {document | some document in principal.ownedDocuments},
        "ownedFolderContents": graph.reachable(children, principal.ownedFolders),
        "ownedFolders": {folder | some folder in principal.ownedFolders},
    } | some principal in input.principals},
    "applicable": {
        "Action::\"read\"": ["view", "ownedDocuments", "ownedFolderContents"],
        "Action::\"write\"": ["ownedDocuments", "ownedFolderContents"],
        "Action::\"share\"": ["ownedDocuments", "ownedFolderContents"],
        "Action::\"changeOwner\"": ["ownedDocuments"],
        "Action::\"createDocument\"": ["ownedFolders"],
    },
}

allow {
    input.action == "Action::\"read\""
    input.resource.isPublic
}

allow {
    capabilities := data.capabilities[input.principal.uid]
    some capability in data.applicable[input.action]
    input.resource.uid in capabilities[capability]
}
