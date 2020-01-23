package model

type JSONRhModels struct {
	Advisory []AdvisoryMid `json:"advisory"`
}
type AdvisoryMid struct {
	AdvisoryMid AdvisoryDetails
	Title       []string `json:"title"`
}

type AdvisoryDetails struct {
	Title       string                 `json:"title"`
	FixesCVE    []string               `json:"fixes_cve"`
	Severity    string                 `json:"severity"`
	AffectedCpe []string               `json:"affected_cpe"`
	Criteria    map[string]interface{} `json:"criteria"`
}

// type JSONRhModels struct {
// 	Advisory []AdvisoryDetails `json:"advisory"`
// 	Title    []string          `json:"title"`
// }

// type AdvisoryDetails struct {
// 	Title       string                 `json:"title"`
// 	FixesCVE    []string               `json:"fixes_cve"`
// 	Severity    string                 `json:"severity"`
// 	AffectedCpe []string               `json:"affected_cpe"`
// 	Criteria    map[string]interface{} `json:"criteria"`
// }
