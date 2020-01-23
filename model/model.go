package model

type AdvisoryDetails struct {
	Title       string                 `json:"title"`
	FixesCVE    []string               `json:"fixes_cve"`
	Severity    string                 `json:"severity"`
	AffectedCpe []string               `json:"affected_cpe"`
	Criteria    map[string]interface{} `json:"criteria"`
}

type Title struct {
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
