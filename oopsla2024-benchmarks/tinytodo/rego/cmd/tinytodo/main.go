package main

import (
	"TinyTodoRego/tinytodo"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/open-policy-agent/opa/rego"
	"os"
	"time"
)

func main() {
	benchmarkCase := flag.String("case", "original", "original, input-excluded or closure-prepared")
	flag.Parse()
	if *benchmarkCase != "original" && *benchmarkCase != "input-excluded" && *benchmarkCase != "closure-prepared" {
		panic("unsupported benchmark case: " + *benchmarkCase)
	}
	inputs := tinytodo.ReadInput()
	outputs := runExpirement(inputs, *benchmarkCase)
	tinytodo.WriteOutput(outputs)
}

func runExpirement(input tinytodo.Input, benchmarkCase string) []tinytodo.TestData {
	outputs := make([]tinytodo.TestData, len(input.Requests), len(input.Requests))
	start := time.Now()
	var policyObj rego.PreparedEvalQuery
	var compilation, preprocessing time.Duration
	if benchmarkCase == "closure-prepared" {
		policyObj, preprocessing, compilation = tinytodo.PreparePolicy(input)
	} else {
		policyObj = tinytodo.ReadPolicy(input.Policy, input.Namespace)
		compilation = time.Since(start)
	}

	var conversion *int64
	if benchmarkCase == "original" {
		for i, request := range input.Requests {
			casted := request.(map[string]interface{})
			outputs[i] = tinytodo.IsAuthorized(casted, policyObj)
		}
	} else {
		start = time.Now()
		parsed := tinytodo.ParseRequests(input.Requests)
		nanoseconds := time.Since(start).Nanoseconds()
		conversion = &nanoseconds
		for i, request := range parsed {
			outputs[i] = tinytodo.IsAuthorizedParsed(request, policyObj)
		}
	}
	setup, err := json.Marshal(map[string]interface{}{
		"app": input.Namespace, "case": benchmarkCase,
		"requests": len(input.Requests), "compilation_ns": compilation.Nanoseconds(),
		"input_conversion_ns": conversion,
		"preprocessing_ns":    preprocessing.Nanoseconds(),
	})
	if err != nil {
		panic(err)
	}
	fmt.Fprintf(os.Stderr, "opa_setup %s\n", setup)
	return outputs
}
