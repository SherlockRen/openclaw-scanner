package models

type Authorization struct {
	Requester  string
	Scope      string
	TimeWindow string
	Source     string
}

type Finding struct {
	FindingID            string `json:"findingId"`
	FindingType          string `json:"findingType"`
	Severity             string `json:"severity"`
	RuleID               string `json:"ruleId"`
	Target               string `json:"target"`
	Port                 int    `json:"port,omitempty"`
	AccessURL            string `json:"accessUrl,omitempty"`
	EvidencePattern      string `json:"evidencePattern"`
	EvidenceMasked       string `json:"evidenceMasked"`
	Confidence           string `json:"confidence"`
	RequiresManualReview bool   `json:"requiresManualReview"`
	FalsePositiveState   string `json:"falsePositiveState"`
	Recommendation       string `json:"recommendation"`
}

type HostScan struct {
	Target    string
	OpenPorts []int
	Services  map[int]string
	Products  map[int]string
	Versions  map[int]string
}

type TaskMeta struct {
	TaskID      string `json:"taskId"`
	StartedAt   string `json:"startedAt"`
	EndedAt     string `json:"endedAt"`
	Status      string `json:"status"`
	TargetCount int    `json:"targetCount"`
	PortCount   int    `json:"portCount"`
}

type Summary struct {
	FindingCount int `json:"findingCount"`
}

type Report struct {
	SchemaVersion string    `json:"schemaVersion"`
	TaskMeta      TaskMeta  `json:"taskMeta"`
	Summary       Summary   `json:"summary"`
	Findings      []Finding `json:"findings"`
}
