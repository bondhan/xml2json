package model

type UnitData map[string][]string

type AdvisoryDetails struct {
	Title       string     `json:"title"`
	FixesCVE    []string   `json:"fixes_cve"`
	Severity    string     `json:"severity"`
	AffectedCpe []string   `json:"affected_cpe"`
	Criteria    []UnitData `json:"criteria"`
}

type Title struct {
	Title string `json:"title"`
}
