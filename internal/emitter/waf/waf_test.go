package waf_test

/*

func TestWAF(t *testing.T) {
	t.Parallel()

	type arrange struct {
		rules []rule.Rule
	}

	testCases := map[string]struct {
		arrange     arrange
		wafOpCtx    *wafcontext.WafOperationContext
		inspectData inspector.InspectData
		expectBlock bool
	}{
		"detect with mock inspector": {
			arrange: arrange{
				rules: []rule.Rule{
					{
						ID:     "1",
						Name:   "Detect Malicious URL by Mock Inspector",
						Action: "block",
						Conditions: []rule.Condition{
							{
								Inspector: "mock",
								InspectTarget: []rule.InspectTarget{
									{Target: "http.request.url"},
								},
							},
						},
					},
				},
			},
			wafOpCtx: wafcontext.NewWafOperationContext(wafcontext.WithHttpRequstContext(wafcontext.HttpRequest{
				URL:      "http://malicious.com",
				Headers:  http.Header{"Host": []string{"malicious.com"}},
				Body:     map[string][]string{},
				ClientIP: "10.0.1.1",
			})),
			inspectData: inspector.InspectData{
				Target: map[inspector.InspectTarget]types.InspectTargetValue{
					inspector.InspectTargetHttpRequestURL: types.NewStringValue("http://malicious.com"),
				},
			},
			expectBlock: true,
		},
		"detect with mock inspector, but monitor": {
			arrange: arrange{
				rules: []rule.Rule{
					{
						ID:     "1",
						Name:   "Detect Malicious URL by Mock Inspector",
						Action: "monitor",
						Conditions: []rule.Condition{
							{
								Inspector: "mock",
								InspectTarget: []rule.InspectTarget{
									{Target: "http.request.url"},
								},
							},
						},
					},
				},
			},
			wafOpCtx: wafcontext.NewWafOperationContext(wafcontext.WithHttpRequstContext(wafcontext.HttpRequest{
				URL:      "http://malicious.com",
				Headers:  http.Header{"Host": []string{"malicious.com"}},
				Body:     map[string][]string{},
				ClientIP: "10.0.1.1",
			})),
			inspectData: inspector.InspectData{
				Target: map[inspector.InspectTarget]types.InspectTargetValue{
					inspector.InspectTargetHttpRequestURL: types.NewStringValue("http://malicious.com"),
				},
			},
			expectBlock: false,
		},
		"when not malicious url, do not detect with mock inspector": {
			arrange: arrange{
				rules: []rule.Rule{
					{
						ID:     "2",
						Name:   "Detect Malicious URL by Mock Inspector",
						Action: "block",
						Conditions: []rule.Condition{
							{
								Inspector:     "mock",
								InspectTarget: []rule.InspectTarget{{Target: "http.request.url"}},
							},
						},
					},
				},
			},
			wafOpCtx: wafcontext.NewWafOperationContext(wafcontext.WithHttpRequstContext(wafcontext.HttpRequest{
				URL:      "http://example.com",
				Headers:  http.Header{"Host": []string{"example.com"}},
				Body:     map[string][]string{},
				ClientIP: "10.0.1.1",
			})),
			inspectData: inspector.InspectData{
				Target: map[inspector.InspectTarget]types.InspectTargetValue{
					inspector.InspectTargetHttpRequestURL: types.NewStringValue("http://example.com"),
				},
			},
			expectBlock: false,
		},
		"If there are multiple conditions and only one of them is met, it should not be detected": {
			arrange: arrange{
				rules: []rule.Rule{
					{
						ID:     "3",
						Name:   "Detect Malicious URL",
						Action: "block",
						Conditions: []rule.Condition{
							{
								Inspector:     "mock",
								InspectTarget: []rule.InspectTarget{{Target: "http.request.url"}},
							},
							{
								Inspector:     "nothing",
								InspectTarget: []rule.InspectTarget{{Target: "http.request.url"}},
							},
						},
					},
				},
			},
			wafOpCtx: wafcontext.NewWafOperationContext(wafcontext.WithHttpRequstContext(wafcontext.HttpRequest{
				URL:      "http://example.com",
				Headers:  http.Header{"Host": []string{"example.com"}},
				Body:     map[string][]string{},
				ClientIP: "10.0.1.1",
			})),
			inspectData: inspector.InspectData{
				Target: map[inspector.InspectTarget]types.InspectTargetValue{
					inspector.InspectTargetHttpRequestURL: types.NewStringValue("http://example.com"),
				},
			},
			expectBlock: false,
		},
		"Integration test: Regex inspector": {
			arrange: arrange{
				rules: []rule.Rule{
					{
						ID:     "4",
						Name:   "Detect Malicious URL by Regex",
						Action: "block",
						Conditions: []rule.Condition{
							{
								Inspector:     "regex",
								InspectTarget: []rule.InspectTarget{{Target: "http.request.url"}},
								Regex:         "malicious",
							},
						},
					},
				},
			},
			wafOpCtx: wafcontext.NewWafOperationContext(wafcontext.WithHttpRequstContext(wafcontext.HttpRequest{
				URL:      "http://malicious.com",
				Headers:  http.Header{"Host": []string{"malicious.com"}},
				Body:     map[string][]string{},
				ClientIP: "10.0.1.1",
			})),
			inspectData: inspector.InspectData{
				Target: map[inspector.InspectTarget]types.InspectTargetValue{
					inspector.InspectTargetHttpRequestURL: types.NewStringValue("http://malicious.com"),
				},
			},
			expectBlock: true,
		},
		"Integration test: Regex inspector with specify key": {
			arrange: arrange{
				rules: []rule.Rule{
					{
						ID:     "4",
						Name:   "Detect Malicious URL by Regex",
						Action: "block",
						Conditions: []rule.Condition{
							{
								Inspector:     "regex",
								InspectTarget: []rule.InspectTarget{{Target: "http.request.header", Keys: []string{"Host"}}},
								Regex:         "malicious\\.com",
							},
						},
					},
				},
			},
			wafOpCtx: wafcontext.NewWafOperationContext(wafcontext.WithHttpRequstContext(wafcontext.HttpRequest{
				URL:      "http://example.com",
				Headers:  http.Header{"Host": []string{"malicious.com"}},
				Body:     map[string][]string{},
				ClientIP: "10.0.1.1",
			})),
			inspectData: inspector.InspectData{
				Target: map[inspector.InspectTarget]types.InspectTargetValue{
					inspector.InspectTargetHttpRequestHeader: types.NewKeyValues(http.Header{
						"Host": []string{"malicious.com"},
					}),
				},
			},
			expectBlock: true,
		},
	}

	for name, tt := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rules := &rule.RuleSet{
				Version: "1.0",
				Rules:   tt.arrange.rules,
			}

			w := waf.NewWAF(rules)
			w.RegisterInspector("mock", &MockInspector{})
			w.RegisterInspector("nothing", &NopInspector{})

			err := w.Inspect(tt.wafOpCtx, tt.inspectData)

			if tt.expectBlock {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
		})
	}
}
*/
