package model

import "encoding/xml"

//Oval ...
type Oval struct {
	// XMLName           xml.Name    `xml:"oval_definitions" json:"ovalDefinitions"`
	Xmlns             string      `xml:"xmlns,attr" json:"xmlns"`
	XmlnsOval         string      `xml:"oval,attr" json:"oval"`
	XmlnsOvalDef      string      `xml:"oval-def,attr" json:"ovalDef"`
	XmlnsUnixDef      string      `xml:"unix-def,attr" json:"unixDef"`
	XmlnsRedDef       string      `xml:"red-def,attr" json:"redDef"`
	XmlnsXsi          string      `xml:"xsi,attr" json:"xsi"`
	XsiSchemaLocation string      `xml:"schemaLocation,attr" json:"schemaLocations"`
	Generator         generator   `xml:"generator" json:"generator"`
	Definitions       definitions `xml:"definitions" json:"definitions"`
	Tests             tests       `xml:"tests" json:"tests"`
	Objects           objects     `xml:"objects" json:"objects"`
	// States            states      `xml:"states" json:"states"`
}

type generator struct {
	// XMLName           xml.Name `xml:"generator" json:"generator"`
	OvalProductName   string `xml:"product_name" json:"productName"`
	OvalSchemaVersion string `xml:"schema_version" json:"schemaVersion"`
	OvalTimestamp     string `xml:"timestamp" json:"timestamp"`
}

type definitions struct {
	Definition definition `xml:"definition" json:"definition"`
}

type definition struct {
	// XMLName xml.Name `xml:"definition" json:"definition"`
	Class    string   `xml:"class,attr" json:"class"`
	ID       string   `xml:"id,attr" json:"id"`
	Version  string   `xml:"version,attr" json:"version"`
	Metadata metadata `xml:"metadata" json:"metadata"`
	Criteria criteria `xml:"criteria" json:"criteria,omitempty"`
}

type metadata struct {
	// XMLName     xml.Name    `xml:"metadata" json:"metadata"`
	Title       string      `xml:"title" json:"title"`
	Affected    affected    `xml:"affected" json:"affected"`
	Reference   []reference `xml:"reference" json:"reference"`
	Description string      `xml:"description" json:"description"`
	Advisory    advisory    `xml:"advisory" json:"advisory"`
}

type affected struct {
	// XMLName  xml.Name `xml:"affected" json:"affected"`
	Family   string   `xml:"family,attr" json:"family"`
	Platform []string `xml:"platform" json:"platform"`
}

type reference struct {
	XMLName xml.Name `xml:"reference" json:"reference"`
	RefID   string   `xml:"ref_id,attr" json:"refId"`
	RefURL  string   `xml:"ref_url,attr" json:"refUrl"`
	Source  string   `xml:"source,attr" json:"source"`
}
type advisory struct {
	// XMLName     xml.Name `xml:"advisory" json:"advisory"`
	From     string  `xml:"from,attr" json:"from"`
	Severity string  `xml:"severity" json:"severity"`
	Rights   string  `xml:"rights" json:"rights"`
	Issued   issued  `xml:"issued" json:"issued"`
	Updated  updated `xml:"updated" json:"updated"`
}

type issued struct {
	IssuedDate string `xml:"date,attr" json:"date"`
}

type updated struct {
	UpdatedDate string `xml:"date,attr" json:"date"`
}

type criteria struct {
	// XMLName   xml.Name   `xml:"criteria"`
	CriteriaOperator string      `xml:"operator,attr" json:"operator"`
	Criterion        []criterion `xml:"criterion" json:"criterion,omitempty"`
	Criteria         []criteria  `xml:"criteria" json:"criteria,omitempty"`
}

type criterion struct {
	Comment string `xml:"comment,attr" json:"comment"`
	TestRef string `xml:"test_ref,attr" json:"testRef"`
}

type tests struct {
	// XMLName   xml.Name `xml:"tests"`
	RpmInfo   []rpminfo   `xml:"rpminfo_test" json:"rpmInfoTest"`
	RpmVerify []rpmverify `xml:"rpmverifyfile_test" json:"rpmVerifyFileTest"`
}

type rpminfo struct {
	Xmlns   string `xml:"xmlns,attr" json:"xmlns"`
	Check   string `xml:"check,attr" json:"check"`
	Comment string `xml:"comment,attr" json:"comment"`
	ID      string `xml:"id,attr" json:"id"`
	Version string `xml:"version,attr" json:"version"`

	Object obj   `xml:"object" json:"object"`
	State  state `xml:"state" json:"state"`
}

type rpmverify struct {
	Xmlns   string `xml:"xmlns,attr" json:"xmlns"`
	Check   string `xml:"check,attr" json:"check"`
	Comment string `xml:"comment,attr" json:"comment"`
	ID      string `xml:"id,attr" json:"id"`
	Version string `xml:"version,attr" json:"version"`

	Object obj   `xml:"object" json:"object"`
	State  state `xml:"state" json:"state"`
}

type obj struct {
	ObjectRef string `xml:"object_ref,attr" json:"objectRef"`
}

type state struct {
	StateRef string `xml:"state_ref,attr" json:"stateRef"`
}

type objects struct {
	// XMLName       xml.Name `xml:"objects"`
	RpmInfoObject   []rpminfoobject   `xml:"rpminfo_object"`
	RpmVerifyObject []rpmverifyobject `xml:"rpmverifyfile_object"`
}

type rpminfoobject struct {
	Xmlns   string `xml:"xmlns,attr" json:"xmlns"`
	ID      string `xml:"id,attr" json:"id"`
	Version string `xml:"version,attr" json:"version"`
	Name    string `xml:"name" json:"name"`
}
type rpmverifyobject struct {
	Xmlns   string `xml:"xmlns,attr" json:"xmlns"`
	ID      string `xml:"id,attr" json:"id"`
	Version string `xml:"version,attr" json:"version"`
}

type states struct {
	// XMLName xml.Name `xml:"states"`
}
