// Package aiassist implements a provider-agnostic post-exploitation assistant
// with tool calling.
//
// The assistant never executes anything by itself: it proposes tool calls, and
// the policy engine decides whether a call may run.  Read-only tools may run
// automatically; every write or destructive tool must be explicitly confirmed
// by the human operator (pass its name in Result.confirmed) and every decision
// is written to the audit log with the evidence (tool output) attached.
//
// Any OpenAI-compatible endpoint works (hosted providers, a local llama.cpp /
// vLLM / Ollama gateway exposing /v1/chat/completions, ...).  Custom backends
// can implement Provider.
package aiassist

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ---------- provider interface ----------

// Message is one chat message in OpenAI format.
type Message struct {
	Role       string     `json:"role"`
	Content    string     `json:"content,omitempty"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
	Name       string     `json:"name,omitempty"`
}

// ToolCall is a function invocation proposed by the model.
type ToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

// ToolDef describes a function exposed to the model.
type ToolDef struct {
	Type     string      `json:"type"`
	Function FunctionDef `json:"function"`
}

// FunctionDef is the OpenAI function schema.
type FunctionDef struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
}

// ChatRequest is a provider-neutral completion request.
type ChatRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	Tools       []ToolDef `json:"tools,omitempty"`
	Temperature float64   `json:"temperature"`
	MaxTokens   int       `json:"max_tokens,omitempty"`
}

// ChatResponse is one assistant turn.
type ChatResponse struct {
	Message Message
	Usage   map[string]int
}

// Provider abstracts a chat completion backend.
type Provider interface {
	Chat(ctx context.Context, req ChatRequest) (*ChatResponse, error)
}

// OpenAIProvider talks to any OpenAI-compatible /chat/completions endpoint.
type OpenAIProvider struct {
	BaseURL string // e.g. https://api.example.com/v1 or http://127.0.0.1:11434/v1
	APIKey  string // optional for local endpoints
	Model   string
	HTTP    *http.Client
}

// Chat implements Provider.
func (p *OpenAIProvider) Chat(ctx context.Context, req ChatRequest) (*ChatResponse, error) {
	if strings.TrimSpace(p.BaseURL) == "" {
		return nil, errors.New("ai: base URL is not configured")
	}
	if req.Model == "" {
		req.Model = p.Model
	}
	if req.MaxTokens == 0 {
		req.MaxTokens = 1200
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	url := strings.TrimRight(p.BaseURL, "/") + "/chat/completions"
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	hreq.Header.Set("Content-Type", "application/json")
	if p.APIKey != "" {
		hreq.Header.Set("Authorization", "Bearer "+p.APIKey)
	}
	hc := p.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 120 * time.Second}
	}
	resp, err := hc.Do(hreq)
	if err != nil {
		return nil, fmt.Errorf("ai: request: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("ai: provider HTTP %d: %s", resp.StatusCode, truncate(string(raw), 500))
	}
	var out struct {
		Choices []struct {
			Message Message `json:"message"`
		} `json:"choices"`
		Usage map[string]int `json:"usage"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("ai: bad provider response: %w", err)
	}
	if len(out.Choices) == 0 {
		return nil, errors.New("ai: provider returned no choices")
	}
	return &ChatResponse{Message: out.Choices[0].Message, Usage: out.Usage}, nil
}

// ---------- tool registry & policy ----------

// Risk classifies a tool.
type Risk string

const (
	RiskRead        Risk = "read"
	RiskWrite       Risk = "write"
	RiskDestructive Risk = "destructive"
)

// Tool is a bounded capability the assistant may use.
type Tool struct {
	Name        string
	Description string
	Risk        Risk
	// Params is the JSON schema object for the arguments.
	Params json.RawMessage
	// Call runs the tool.  It must be idempotent for RiskRead.
	Call func(ctx context.Context, args json.RawMessage) (any, error)
}

// Step records one proposed/executed tool call.  Steps are the evidence the
// assistant is required to cite.
type Step struct {
	Tool       string          `json:"tool"`
	Args       json.RawMessage `json:"args"`
	Risk       Risk            `json:"risk"`
	Allowed    bool            `json:"allowed"`
	Reason     string          `json:"reason,omitempty"`
	Result     json.RawMessage `json:"result,omitempty"`
	Error      string          `json:"error,omitempty"`
	DurationMS int64           `json:"duration_ms"`
}

// Result is the outcome of one Ask.
type Result struct {
	Answer     string          `json:"answer"`
	Steps      []Step          `json:"steps"`
	Usage      map[string]int  `json:"usage,omitempty"`
	NeedApprove []string       `json:"need_approve,omitempty"` // tool names waiting for human confirmation
	Evidence   json.RawMessage `json:"evidence,omitempty"`     // compact evidence bundle for the report
	Model      string          `json:"model,omitempty"`
}

// AuditFunc records an assistant decision.
type AuditFunc func(actor, action, target, detail string)

// Assistant coordinates provider + tools + policy.
type Assistant struct {
	Provider Provider
	Model    string
	Tools    map[string]*Tool
	Order    []string
	// AutoRead allows read-only tools without confirmation (default true).
	AutoRead bool
	// MaxRounds bounds the tool-calling loop.
	MaxRounds int
	Audit     AuditFunc

	mu sync.RWMutex
}

// New builds an assistant.  autoRead defaults to true.
func New(p Provider, model string) *Assistant {
	return &Assistant{Provider: p, Model: model, Tools: map[string]*Tool{}, AutoRead: true, MaxRounds: 6}
}

// Register adds a tool.
func (a *Assistant) Register(t Tool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.Tools[t.Name]; !ok {
		a.Order = append(a.Order, t.Name)
	}
	a.Tools[t.Name] = &t
}

// ToolList returns tool definitions in registration order.
func (a *Assistant) ToolList() []ToolDef {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]ToolDef, 0, len(a.Order))
	for _, n := range a.Order {
		t := a.Tools[n]
		params := t.Params
		if len(params) == 0 {
			params = json.RawMessage(`{"type":"object","properties":{}}`)
		}
		out = append(out, ToolDef{Type: "function", Function: FunctionDef{Name: t.Name, Description: t.Description, Parameters: params}})
	}
	return out
}

// Describe returns tool metadata (name/risk/description) for the operator UI.
func (a *Assistant) Describe() []map[string]any {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]map[string]any, 0, len(a.Order))
	for _, n := range a.Order {
		t := a.Tools[n]
		out = append(out, map[string]any{"name": t.Name, "risk": t.Risk, "description": t.Description})
	}
	return out
}

// systemPrompt pins the safety contract.
const systemPrompt = `You are a post-exploitation assistant inside an authorized red-team C2 platform.
Rules that override everything else:
1. You never invent facts. Only reference tool output you actually received.
2. Read-only tools (risk=read) may be called directly. Any write or destructive tool must be
   requested from the human operator; the platform will ask for confirmation and may refuse.
3. When you propose a destructive action, explain the expected impact, the rollback, and the
   exact evidence (tool name + key output lines) that justifies it.
4. Prefer the least invasive action that answers the question. Do not chain destructive actions.
5. Reply in the operator's language, concise, with evidence citations like [sysinfo] or [tasks: <id>].`

// Ask runs one assistant turn with a bounded tool loop.
//
// confirmed lists tool names the human has already approved for this call.  A
// destructive tool not in that list is NOT executed; it is returned in
// NeedApprove so the caller can show a confirmation prompt and re-ask.
func (a *Assistant) Ask(ctx context.Context, actor, prompt string, confirmed []string) (*Result, error) {
	if a.Provider == nil {
		return nil, errors.New("ai: no provider configured")
	}
	allow := map[string]bool{}
	for _, n := range confirmed {
		allow[n] = true
	}
	msgs := []Message{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: prompt},
	}
	res := &Result{Model: a.Model}
	maxRounds := a.MaxRounds
	if maxRounds <= 0 {
		maxRounds = 6
	}
	for round := 0; round < maxRounds; round++ {
		resp, err := a.Provider.Chat(ctx, ChatRequest{Model: a.Model, Messages: msgs, Tools: a.ToolList(), Temperature: 0.1})
		if err != nil {
			return res, err
		}
		if resp.Usage != nil {
			res.Usage = resp.Usage
		}
		am := resp.Message
		if am.Role == "" {
			am.Role = "assistant"
		}
		msgs = append(msgs, am)
		if len(am.ToolCalls) == 0 {
			res.Answer = am.Content
			break
		}
		for _, tc := range am.ToolCalls {
			step := a.execute(ctx, actor, tc, allow)
			res.Steps = append(res.Steps, step)
			if step.Reason == "needs human approval" {
				res.NeedApprove = append(res.NeedApprove, step.Tool)
				// Return immediately: do not let the model keep going after a
				// blocked destructive call.
				res.Answer = am.Content
				if res.Answer == "" {
					res.Answer = "Awaiting operator approval for: " + strings.Join(res.NeedApprove, ", ")
				}
				res.Evidence = evidence(res.Steps)
				return res, nil
			}
			payload := step.Result
			if step.Error != "" {
				payload, _ = json.Marshal(map[string]string{"error": step.Error})
			}
			if len(payload) == 0 {
				payload = json.RawMessage(`null`)
			}
			msgs = append(msgs, Message{Role: "tool", ToolCallID: tc.ID, Name: step.Tool, Content: string(payload)})
		}
	}
	if res.Evidence == nil {
		res.Evidence = evidence(res.Steps)
	}
	return res, nil
}

func (a *Assistant) execute(ctx context.Context, actor string, tc ToolCall, allow map[string]bool) Step {
	st := Step{Tool: tc.Function.Name, Args: json.RawMessage(defaultJSON(tc.Function.Arguments)), DurationMS: 0}
	start := time.Now()
	defer func() { st.DurationMS = time.Since(start).Milliseconds() }()
	a.mu.RLock()
	t := a.Tools[tc.Function.Name]
	a.mu.RUnlock()
	if t == nil {
		st.Reason = "unknown tool"
		st.Error = "unknown tool " + tc.Function.Name
		a.audit(actor, "ai.tool", tc.Function.Name, "rejected: unknown tool")
		return st
	}
	st.Risk = t.Risk
	okPolicy := false
	switch t.Risk {
	case RiskRead:
		okPolicy = a.AutoRead
	case RiskWrite, RiskDestructive:
		okPolicy = allow[tc.Function.Name]
	default:
		okPolicy = false
	}
	if !okPolicy {
		st.Reason = "needs human approval"
		a.audit(actor, "ai.tool", t.Name, "blocked: awaiting approval (risk="+string(t.Risk)+")")
		return st
	}
	st.Allowed = true
	v, err := t.Call(ctx, st.Args)
	if err != nil {
		st.Error = err.Error()
		st.Reason = "tool error"
		b, _ := json.Marshal(map[string]string{"error": err.Error()})
		st.Result = b
		a.audit(actor, "ai.tool", t.Name, "error: "+truncate(err.Error(), 300))
		return st
	}
	b, err := json.Marshal(v)
	if err != nil {
		st.Error = err.Error()
		st.Result = json.RawMessage(`{}`)
		return st
	}
	st.Result = b
	a.audit(actor, "ai.tool", t.Name, "ok; args="+truncate(string(st.Args), 400)+"; out="+truncate(string(b), 400))
	return st
}

func (a *Assistant) audit(actor, action, target, detail string) {
	if a.Audit != nil {
		a.Audit(actor, action, target, detail)
	}
}

// evidence compacts executed steps into a citation bundle.
func evidence(steps []Step) json.RawMessage {
	type ev struct {
		Tool   string `json:"tool"`
		Args   string `json:"args,omitempty"`
		Output string `json:"output,omitempty"`
		Error  string `json:"error,omitempty"`
	}
	out := make([]ev, 0, len(steps))
	for _, s := range steps {
		if !s.Allowed {
			continue
		}
		out = append(out, ev{Tool: s.Tool, Args: truncate(string(s.Args), 400), Output: truncate(string(s.Result), 2000), Error: s.Error})
	}
	b, _ := json.Marshal(out)
	return b
}

func defaultJSON(s string) string {
	if strings.TrimSpace(s) == "" {
		return "{}"
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
