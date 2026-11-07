package tinytodo

import (
	"os"
	"testing"
)

func TestParsedInputMatchesOriginalTinyTodoAlternatives(t *testing.T) {
	policy, err := os.ReadFile("../tinytodo.rego")
	if err != nil {
		t.Fatal(err)
	}
	query := ReadPolicy(string(policy), "tinytodo")
	preparedPolicy, err := os.ReadFile("../../../prepared-policies/tinytodo.rego")
	if err != nil {
		t.Fatal(err)
	}
	for _, testcase := range []struct {
		name    string
		readers []interface{}
		writers []interface{}
		want    bool
	}{
		{"group reader", []interface{}{"group"}, nil, true},
		{"group writer can read", nil, []interface{}{"group"}, true},
		{"no permission", nil, nil, false},
	} {
		t.Run(testcase.name, func(t *testing.T) {
			readers, writers := testcase.readers, testcase.writers
			if readers == nil {
				readers = []interface{}{}
			}
			if writers == nil {
				writers = []interface{}{}
			}
			input := map[string]interface{}{
				"Request": map[string]interface{}{
					"Principal": "user", "Action": `Action::"GetList"`,
					"Resource": map[string]interface{}{
						"Owner": "other", "Readers": readers, "Writers": writers,
					},
				},
				"Data": map[string]interface{}{
					"Groups": map[string]interface{}{
						"user": []interface{}{"team"}, "team": []interface{}{"group"},
						"group": []interface{}{},
					},
				},
			}
			parsed := ParseRequests([]interface{}{input})
			if got := IsAuthorized(input, query).Decision; got != testcase.want {
				t.Fatalf("original decision = %v, want %v", got, testcase.want)
			}
			if got := IsAuthorizedParsed(parsed[0], query).Decision; got != testcase.want {
				t.Fatalf("parsed decision = %v, want %v", got, testcase.want)
			}
			prepared, _, _ := PreparePolicy(Input{
				Policy: string(preparedPolicy), Namespace: "tinytodo",
				Requests: []interface{}{input},
			})
			if got := IsAuthorizedParsed(parsed[0], prepared).Decision; got != testcase.want {
				t.Fatalf("closure-prepared decision = %v, want %v", got, testcase.want)
			}
		})
	}
}

func TestGDrivePreparesPrincipalsAbsentFromFirstRequest(t *testing.T) {
	policy, err := os.ReadFile("../../../prepared-policies/gdrive.rego")
	if err != nil {
		t.Fatal(err)
	}
	principal := func(uid string, owned []interface{}) map[string]interface{} {
		return map[string]interface{}{
			"uid": uid, "ownedDocuments": owned,
			"ownedFolders":                      []interface{}{},
			"documentsAndFoldersWithViewAccess": []interface{}{},
		}
	}
	first, second := principal("first", []interface{}{}), principal("second", []interface{}{"document"})
	request := map[string]interface{}{
		"principal": first, "action": `Action::"write"`,
		"resource": map[string]interface{}{"uid": "document", "isPublic": false},
		"files":    map[string]interface{}{"document": []interface{}{}},
	}
	query, _, _ := PreparePolicy(Input{
		Policy: string(policy), Namespace: "gdrive",
		Requests: []interface{}{request}, Principals: []interface{}{first, second},
	})
	request["principal"] = second
	parsed := ParseRequests([]interface{}{request})
	if !IsAuthorizedParsed(parsed[0], query).Decision {
		t.Fatal("principal absent from the preparation request should retain ownership permission")
	}
}
