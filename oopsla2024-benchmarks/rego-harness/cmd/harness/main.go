package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/open-policy-agent/opa/v1/rego"
	"os"
	"rego-harness/harness"
	"time"
)

func main() {
	benchmarkCase := flag.String("case", "original", "original, input-excluded or closure-prepared")
	flag.Parse()
	if *benchmarkCase != "original" && *benchmarkCase != "input-excluded" && *benchmarkCase != "closure-prepared" {
		panic("unsupported benchmark case: " + *benchmarkCase)
	}
	inputs := harness.ReadInput()
	outputs := runExperiment(inputs, *benchmarkCase)
	harness.WriteOutput(outputs)
}

func runExperiment(input harness.Input, benchmarkCase string) []harness.TestData {
	outputs := make([]harness.TestData, len(input.Requests))
	start := time.Now()
	var policyObj rego.PreparedEvalQuery
	var compilation, preprocessing time.Duration
	if benchmarkCase == "closure-prepared" {
		policyObj, preprocessing, compilation = harness.PreparePolicy(input)
	} else {
		policyObj = harness.ReadPolicy(input.Policy, input.Namespace)
		compilation = time.Since(start)
	}

	var conversion *int64
	if benchmarkCase == "original" {
		for i, request := range input.Requests {
			casted := request.(map[string]interface{})
			outputs[i] = harness.IsAuthorized(casted, policyObj)
		}
	} else {
		start = time.Now()
		parsed := harness.ParseRequests(input.Requests)
		nanoseconds := time.Since(start).Nanoseconds()
		conversion = &nanoseconds
		for i, request := range parsed {
			outputs[i] = harness.IsAuthorizedParsed(request, policyObj)
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
