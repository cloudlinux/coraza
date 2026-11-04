// Copyright 2026 CloudLinux
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"fmt"
	"strings"

	"github.com/corazawaf/coraza/v3/testing/profile"
)

// sharedLimitTest posts body after query. Rule 5 asserts that ARGS holds
// exactly the limit: the query and body arguments were charged against one
// budget, as in ModSecurity.
func sharedLimitTest(title, query, contentType, body string, deny bool) profile.Test {
	out := profile.ExpectedOutput{
		TriggeredRules:    []int{5},
		NonTriggeredRules: []int{1, 2},
	}
	if deny {
		out = profile.ExpectedOutput{
			TriggeredRules: []int{1, 2, 5},
			Interruption: &profile.ExpectedInterruption{
				Status: 400,
				RuleID: 2,
				Action: "deny",
			},
		}
	}
	return profile.Test{
		Title: title,
		Stages: []profile.Stage{{Stage: profile.SubStage{
			Input: profile.StageInput{
				URI:     "/?" + query,
				Method:  "POST",
				Headers: map[string]string{"content-type": contentType},
				Data:    body,
			},
			Output: out,
		}}},
	}
}

func multipartFields(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "--X\r\nContent-Disposition: form-data; name=\"k%d\"\r\n\r\nv\r\n", i)
	}
	b.WriteString("--X--\r\n")
	return b.String()
}

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "quirky4",
		Description: "Test that exceeding SecArgumentsLimit raises REQBODY_ERROR with the SecArgumentsLimit message and blocks, and that query and body arguments share the limit",
		Enabled:     true,
		Name:        "argumentslimit.yaml",
	},
	Tests: []profile.Test{
		{
			// The payload sits in the trailing members, past the limit, so rule
			// 4 must stay quiet: the arguments cut are the trailing ones and the
			// attacker picks them.
			Title: "arguments limit exceeded blocks and drops the tail",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/",
							Method: "POST",
							Headers: map[string]string{
								"content-type": "application/json",
							},
							Data: `{"k0":"v","k1":"v","k2":"v","k3":"v","k4":"v","k5":"' OR 1=1--","k6":"' OR 1=1--","k7":"' OR 1=1--","k8":"' OR 1=1--","k9":"' OR 1=1--"}`,
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{1, 2},
							NonTriggeredRules: []int{4},
							Interruption: &profile.ExpectedInterruption{
								Status: 400,
								RuleID: 2,
								Action: "deny",
							},
						},
					},
				},
			},
		},
		{
			// The same payload under the limit, so rule 4 is known to match it
			// when the member really reaches inspection.
			Title: "body payload within the limit is inspected",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/",
							Method: "POST",
							Headers: map[string]string{
								"content-type": "application/json",
							},
							Data: `{"k0":"v","k1":"' OR 1=1--"}`,
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{4},
							NonTriggeredRules: []int{1, 2},
						},
					},
				},
			},
		},
		{
			Title: "arguments within limit pass",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/",
							Method: "POST",
							Headers: map[string]string{
								"content-type": "application/json",
							},
							Data: `{"k0":"v","k1":"v","k2":"v"}`,
						},
						Output: profile.ExpectedOutput{
							NonTriggeredRules: []int{1, 2, 4},
						},
					},
				},
			},
		},
		{
			// The payload sits past the limit, so rule 4 must stay quiet: the
			// arguments cut are the trailing ones and the attacker picks them.
			Title: "query string over the limit blocks and drops the tail",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/?a=1&b=2&c=3&d=4&e=5&f=6&evil=%27+OR+1%3D1--+",
							Method: "GET",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{1, 2},
							NonTriggeredRules: []int{4},
							Interruption: &profile.ExpectedInterruption{
								Status: 400,
								RuleID: 2,
								Action: "deny",
							},
						},
					},
				},
			},
		},
		{
			// The same payload under the limit, so rule 4 is known to match it
			// when the argument really reaches inspection.
			Title: "query string payload within the limit is inspected",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/?evil=%27+OR+1%3D1--+",
							Method: "GET",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{4},
							NonTriggeredRules: []int{1, 2},
						},
					},
				},
			},
		},
		{
			Title: "query string within the limit passes",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/?a=1&b=2&c=3",
							Method: "GET",
						},
						Output: profile.ExpectedOutput{
							NonTriggeredRules: []int{1, 2, 4},
						},
					},
				},
			},
		},
		sharedLimitTest("query and JSON values fill the limit together", "q0=v&q1=v", "application/json", `{"a":[0,1,2]}`, false),
		sharedLimitTest("a JSON value past the shared limit blocks", "q0=v&q1=v", "application/json", `{"a":[0,1,2,3]}`, true),
		sharedLimitTest("query at the limit, then a JSON value, blocks", "q0=v&q1=v&q2=v&q3=v&q4=v", "application/json", `{"a":1}`, true),
		// Only a value trips the limit, so a body of empty containers passes.
		sharedLimitTest("query at the limit, then a JSON body without values, passes", "q0=v&q1=v&q2=v&q3=v&q4=v", "application/json", `{"a":{},"b":[]}`, false),
		sharedLimitTest("query and form fields fill the limit together", "q0=v&q1=v", "application/x-www-form-urlencoded", "k0=v&k1=v&k2=v", false),
		sharedLimitTest("a form field past the shared limit blocks", "q0=v&q1=v", "application/x-www-form-urlencoded", "k0=v&k1=v&k2=v&k3=v", true),
		sharedLimitTest("query and multipart fields fill the limit together", "q0=v&q1=v", "multipart/form-data; boundary=X", multipartFields(3), false),
		sharedLimitTest("a multipart field past the shared limit blocks", "q0=v&q1=v", "multipart/form-data; boundary=X", multipartFields(4), true),
	},
	Rules: `
SecRequestBodyAccess On
SecArgumentsLimit 5
SecRule REQUEST_HEADERS:Content-Type "@rx ^application/json" "id:100, phase:1, pass, log, ctl:requestBodyProcessor=JSON"
SecRule REQBODY_ERROR_MSG "@streq SecArgumentsLimit exceeded" "id:1, phase:2, pass, log"
# Declared before the denying rule so they evaluate on the stages that block:
# ARGS_POST is filled in phase 2, and rule 2 ends the transaction there.
SecRule ARGS "@contains 1=1" "id:4, phase:2, pass, log"
SecRule &ARGS "@eq 5" "id:5, phase:2, pass, log"
SecRule REQBODY_ERROR "!@eq 0" "id:2, phase:2, deny, status:400, log"
`,
})
