package harness

import "context"
import "log"
import "time"
import "fmt"

import "github.com/open-policy-agent/opa/v1/rego"
import "github.com/open-policy-agent/opa/v1/ast"
import "github.com/open-policy-agent/opa/v1/storage/inmem"

type Module = func(r *rego.Rego)

func IsAuthorized(input map[string]interface{}, query rego.PreparedEvalQuery) TestData {
	ctx := context.Background()

	start := time.Now()
	evalled := rego.EvalInput(input)
	results, err := query.Eval(ctx, evalled)
	duration := time.Since(start)

	return evaluationResult(results, err, duration)
}

func IsAuthorizedParsed(input ast.Value, query rego.PreparedEvalQuery) TestData {
	ctx := context.Background()
	start := time.Now()
	evalled := rego.EvalParsedInput(input)
	results, err := query.Eval(ctx, evalled)
	duration := time.Since(start)
	return evaluationResult(results, err, duration)
}

func ParseRequests(requests []interface{}) []ast.Value {
	parsed := make([]ast.Value, len(requests))
	for i, request := range requests {
		object, ok := request.(map[string]interface{})
		if !ok {
			panic("expected object authorization request")
		}
		native, err := ast.InterfaceToValue(object)
		if err != nil {
			panic(fmt.Errorf("OPA input conversion failed: %w", err))
		}
		parsed[i] = native
	}
	return parsed
}

func evaluationResult(results rego.ResultSet, err error, duration time.Duration) TestData {
	if err != nil {
		// Handle evaluation error.
		log.Print("Error evaluating policies")
		panic(err)
	}

	var authResult bool

	if len(results) == 0 {
		authResult = false
	} else if was_allowed, ok := results[0].Bindings["x"].(bool); !ok {
		// Handle unexpected result type.
		panic("Unexpected type for `allow`\n")
	} else if was_allowed {
		authResult = true
	} else {
		authResult = false
	}

	return TestData{Decision: authResult, Dur: duration}
}

func ReadPolicy(src string, namespace string) rego.PreparedEvalQuery {
	ctx := context.Background()

	filename := fmt.Sprintf("%s.rego", namespace)
	query_string := fmt.Sprintf("x = data.%s.allow", namespace)

	module := rego.Module(filename, src)
	query, err := rego.New(
		rego.SetRegoVersion(ast.RegoV0),
		rego.Query(query_string),
		module,
	).PrepareForEval(ctx)
	if err != nil {
		log.Print("Error constructing query")
		panic(err)
	}
	return query
}

func PreparePolicy(input Input) (rego.PreparedEvalQuery, time.Duration, time.Duration) {
	if len(input.Requests) == 0 {
		panic("missing request batch for OPA preprocessing")
	}
	first, ok := input.Requests[0].(map[string]interface{})
	if !ok {
		panic("expected object request for OPA preprocessing")
	}
	preparation := first
	if input.Namespace == "gdrive" {
		if input.Principals == nil {
			panic("missing full principal population for GDrive preprocessing")
		}
		preparation = map[string]interface{}{"files": first["files"], "principals": input.Principals}
	}
	ctx := context.Background()
	start := time.Now()
	query, err := rego.New(
		rego.SetRegoVersion(ast.RegoV0),
		rego.Query(fmt.Sprintf("x = data.%s.preprocess", input.Namespace)),
		rego.Module(input.Namespace+".rego", input.Policy),
	).PrepareForEval(ctx)
	if err != nil {
		panic(fmt.Errorf("OPA preprocessing query compilation failed: %w", err))
	}
	results, err := query.Eval(ctx, rego.EvalInput(preparation))
	if err != nil {
		panic(fmt.Errorf("OPA preprocessing failed: %w", err))
	}
	if len(results) != 1 {
		panic("OPA preprocessing must return exactly one result")
	}
	data, ok := results[0].Bindings["x"].(map[string]interface{})
	if !ok {
		panic("OPA preprocessing must return an object")
	}
	preprocessing := time.Since(start)
	start = time.Now()
	prepared, err := rego.New(
		rego.SetRegoVersion(ast.RegoV0),
		rego.Query(fmt.Sprintf("x = data.%s.allow", input.Namespace)),
		rego.Module(input.Namespace+".rego", input.Policy),
		rego.Store(inmem.NewFromObject(data)),
	).PrepareForEval(ctx)
	if err != nil {
		panic(fmt.Errorf("OPA prepared authorization query compilation failed: %w", err))
	}
	return prepared, preprocessing, time.Since(start)
}
