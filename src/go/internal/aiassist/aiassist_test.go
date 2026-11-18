package aiassist

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
)

type scriptedProvider struct {
	mu       sync.Mutex
	requests []ChatRequest
	steps    []Message // one response per round
}

func (p *scriptedProvider) Chat(_ context.Context, req ChatRequest) (*ChatResponse, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.requests = append(p.requests, req)
	if len(p.steps) == 0 {
		return &ChatResponse{Message: Message{Role: "assistant", Content: "done"}}, nil
	}
	m := p.steps[0]
	p.steps = p.steps[1:]
	return &ChatResponse{Message: m, Usage: map[string]int{"total_tokens": 7}}, nil
}

func toolCall(id, name, args string) Message {
	var m Message
	m.Role = "assistant"
	m.ToolCalls = []ToolCall{{ID: id, Type: "function"}}
	m.ToolCalls[0].Function.Name = name
	m.ToolCalls[0].Function.Arguments = args
	return m
}

func TestReadToolAutoExecutesAndIsAudited(t *testing.T) {
	p := &scriptedProvider{steps: []Message{
		toolCall("c1", "list_sessions", `{}`),
		{Role: "assistant", Content: "There are 2 sessions [list_sessions]."},
	}}
	a := New(p, "test")
	var audits []string
	a.Audit = func(actor, action, target, detail string) {
		audits = append(audits, actor+"|"+action+"|"+target+"|"+detail)
	}
	calls := 0
	a.Register(Tool{Name: "list_sessions", Risk: RiskRead, Description: "list", Call: func(ctx context.Context, _ json.RawMessage) (any, error) {
		calls++
		return map[string]int{"count": 2}, nil
	}})
	res, err := a.Ask(context.Background(), "alice", "how many sessions?", nil)
	if err != nil {
		t.Fatalf("Ask: %v", err)
	}
	if calls != 1 {
		t.Fatalf("read tool calls=%d", calls)
	}
	if len(res.Steps) != 1 || !res.Steps[0].Allowed {
		t.Fatalf("step not allowed: %+v", res.Steps)
	}
	if !strings.Contains(res.Answer, "2 sessions") {
		t.Fatalf("answer: %s", res.Answer)
	}
	if len(res.Evidence) == 0 {
		t.Fatalf("missing evidence")
	}
	if len(audits) == 0 || !strings.Contains(audits[0], "ai.tool") {
		t.Fatalf("audit missing: %v", audits)
	}
}

func TestDestructiveToolNeedsConfirmation(t *testing.T) {
	p := &scriptedProvider{steps: []Message{
		toolCall("c1", "shell", `{"sid":"s1","cmd":"whoami"}`),
	}}
	a := New(p, "test")
	ran := false
	a.Register(Tool{Name: "shell", Risk: RiskDestructive, Description: "shell", Call: func(ctx context.Context, _ json.RawMessage) (any, error) {
		ran = true
		return map[string]string{"out": "root"}, nil
	}})
	res, err := a.Ask(context.Background(), "alice", "run whoami", nil)
	if err != nil {
		t.Fatalf("Ask: %v", err)
	}
	if ran {
		t.Fatalf("destructive tool ran without approval")
	}
	if len(res.NeedApprove) != 1 || res.NeedApprove[0] != "shell" {
		t.Fatalf("need_approve=%v", res.NeedApprove)
	}
	if len(res.Steps) != 1 || res.Steps[0].Allowed {
		t.Fatalf("blocked step marked allowed: %+v", res.Steps)
	}

	// Second turn with explicit approval.
	p2 := &scriptedProvider{steps: []Message{
		toolCall("c1", "shell", `{"sid":"s1","cmd":"whoami"}`),
		{Role: "assistant", Content: "done"},
	}}
	a.Provider = p2
	res, err = a.Ask(context.Background(), "alice", "run whoami", []string{"shell"})
	if err != nil {
		t.Fatalf("Ask confirmed: %v", err)
	}
	if !ran {
		t.Fatalf("approved tool did not run")
	}
	if len(res.Steps) != 1 || !res.Steps[0].Allowed {
		t.Fatalf("approved step not allowed: %+v", res.Steps)
	}
	if !strings.Contains(string(res.Steps[0].Result), "root") {
		t.Fatalf("result not captured: %s", res.Steps[0].Result)
	}
}

func TestToolErrorsAndUnknownTools(t *testing.T) {
	p := &scriptedProvider{steps: []Message{
		toolCall("c1", "nope", `{}`),
		toolCall("c2", "boom", `{}`),
		{Role: "assistant", Content: "recovered"},
	}}
	a := New(p, "test")
	a.Register(Tool{Name: "boom", Risk: RiskRead, Call: func(ctx context.Context, _ json.RawMessage) (any, error) {
		return nil, errors.New("kaboom")
	}})
	res, err := a.Ask(context.Background(), "bob", "try things", nil)
	if err != nil {
		t.Fatalf("Ask: %v", err)
	}
	if len(res.Steps) != 2 {
		t.Fatalf("steps=%d", len(res.Steps))
	}
	if res.Steps[0].Error == "" || !strings.Contains(res.Steps[0].Error, "unknown tool") {
		t.Fatalf("unknown tool not reported: %+v", res.Steps[0])
	}
	if res.Steps[1].Error != "kaboom" {
		t.Fatalf("tool error not captured: %+v", res.Steps[1])
	}
	if res.Answer != "recovered" {
		t.Fatalf("answer: %s", res.Answer)
	}
}

func TestToolListSchemas(t *testing.T) {
	a := New(&scriptedProvider{}, "m")
	a.Register(Tool{Name: "z", Risk: RiskRead, Description: "zz", Params: json.RawMessage(`{"type":"object"}`)})
	a.Register(Tool{Name: "a", Risk: RiskWrite, Description: "aa"})
	defs := a.ToolList()
	if len(defs) != 2 || defs[0].Function.Name != "z" || defs[1].Function.Name != "a" {
		t.Fatalf("tool order: %+v", defs)
	}
	if string(defs[1].Function.Parameters) != `{"type":"object","properties":{}}` {
		t.Fatalf("default schema: %s", defs[1].Function.Parameters)
	}
	desc := a.Describe()
	if len(desc) != 2 || desc[1]["risk"] != RiskWrite {
		t.Fatalf("describe: %+v", desc)
	}
}
