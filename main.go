package main

import (
	// "io/ioutil"

	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/beevik/etree"
	"github.com/bondhan/xml2json/model"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
)

var (
	states map[string][]string
)

func check(logger log.Logger, err error) {
	if err != nil {
		logger.Log("Error", err)
		os.Exit(-1)
	}
}

func buildStates(root *etree.Element) {

	states = make(map[string][]string)
	for _, rpminfoState := range root.FindElements("//rpminfo_state") {
		if id := rpminfoState.SelectAttr("id"); id != nil {
			states[id.Value] = []string{}
			if arch := rpminfoState.SelectElement("arch"); arch != nil {
				if opr := arch.SelectAttr("operation"); opr != nil {
					states[id.Value] = append(states[id.Value], opr.Value, "arch")
				}
			}

			if evr := rpminfoState.SelectElement("evr"); evr != nil {
				states[id.Value] = append(states[id.Value], evr.Text())
				if dtType := evr.SelectAttr("datatype"); dtType != nil {
					states[id.Value] = append(states[id.Value], dtType.Value)
					if evrOpr := evr.SelectAttr("operation"); evrOpr != nil {
						states[id.Value] = append(states[id.Value], evrOpr.Value, "evr")
					}
				}
			}

			if sign := rpminfoState.SelectElement("signature_keyid"); sign != nil {
				states[id.Value] = append(states[id.Value], sign.Text())
				if opr := sign.SelectAttr("operation"); opr != nil {
					states[id.Value] = append(states[id.Value], opr.Value, "signature_keyid")
				}
			}

		}
	}

	for _, rpminfoState := range root.FindElements("//rpmverifyfile_state") {
		if id := rpminfoState.SelectAttr("id"); id != nil {
			states[id.Value] = []string{}
			if name := rpminfoState.SelectElement("name"); name != nil {
				states[id.Value] = append(states[id.Value], name.Text())
				if opr := name.SelectAttr("operation"); opr != nil {
					states[id.Value] = append(states[id.Value], opr.Value)
				}
			}

			if ver := rpminfoState.SelectElement("version"); ver != nil {
				states[id.Value] = append(states[id.Value], ver.Text())
				if opr := ver.SelectAttr("operation"); opr != nil {
					states[id.Value] = append(states[id.Value], opr.Value)
				}
			}

		}
	}

	for id, val := range states {
		fmt.Println("id:", id)
		fmt.Println("properties:")
		for _, s := range val {
			fmt.Println("        ", s)
		}
	}
	fmt.Println()

}

func parseCriterion(crit *etree.Element) []string {
	var criteon []string
	for _, criterion := range crit.SelectElements("criterion") {
		if testRef := criterion.SelectAttr("test_ref"); testRef != nil {
			fmt.Printf("test_ref: %s\n", testRef.Value)
			criteon = append(states[testRef.Value])
		}
		if comment := criterion.SelectAttr("comment"); comment != nil {
			fmt.Printf("comment: %s\n", comment.Value)
		}
	}

	return criteon
}

func recParseCriteria(parent *etree.Element, mp []model.UnitData) string {

	for _, crit := range parent.SelectElements("criteria") {
		if opr := crit.SelectAttr("operator"); opr != nil {
			if strings.EqualFold(opr.Value, "OR") || strings.EqualFold(opr.Value, "AND") {

				fmt.Printf("operator: %s\n", opr.Value)

				ret := parseCriterion(crit)
				newMap := make(map[string][]string)

				if ret != nil && len(ret) > 0 {
					newMap[opr.Value] = ret
					mp = append(mp, newMap)
				}

				recParseCriteria(crit, mp)
			}
		}
	}
	//walk through the criteria  and when matching the states, insert the state according to id

	fmt.Println()
	return ""
}

func parseCriteria(root *etree.Element) []model.UnitData {

	m := []model.UnitData{}

	defs := root.SelectElement("definitions")
	def := defs.SelectElement("definition")
	_ = def
	for _, crit := range def.SelectElements("criteria") {
		if opr := crit.SelectAttr("operator"); opr != nil {
			if strings.EqualFold(opr.Value, "OR") || strings.EqualFold(opr.Value, "AND") {
				fmt.Printf("operator: %s\n", opr.Value)

				ret := parseCriterion(crit)
				newMap := make(map[string][]string)

				if ret != nil && len(ret) > 0 {
					newMap[opr.Value] = ret
					m = append(m, newMap)
				}

				recParseCriteria(crit, m)
			}
		}
	}
	//walk through the criteria  and when matching the states, insert the state according to id

	fmt.Println()
	return m
}

func main() {

	logger := log.NewLogfmtLogger(os.Stdout)
	logger = level.NewFilter(logger, level.AllowAll())

	fs := flag.NewFlagSet("xml", flag.ExitOnError)
	xmlInput := fs.String("url", "https://www.redhat.com/security/data/oval/com.redhat.rhsa-20130696.xml", "xml url")

	if len(os.Args) >= 2 {
		fs.Parse(os.Args[2:])
	} else {
		logger.Log("Info", "No URL specified, downloading default https://www.redhat.com/security/data/oval/com.redhat.rhsa-20130696.xml")
		fs.Usage()
	}

	resp, err := http.Get(*xmlInput)
	if err != nil {
		logger.Log("Error", err)
		os.Exit(-1)
	}
	defer resp.Body.Close()

	// Create the file
	out, err := os.Create("file/input.xml")
	if err != nil {
		logger.Log("Error", err)
		os.Exit(-1)
	}
	defer out.Close()

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		logger.Log("Error", err)
		os.Exit(-1)
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromFile("file/input.xml"); err != nil {
		panic(err)
	}

	AdvisoryDetails := model.AdvisoryDetails{}
	Title := model.Title{
		Title: "...",
	}

	root := doc.SelectElement("oval_definitions")

	//title
	for _, md := range root.FindElements("//metadata") {
		AdvisoryDetails.Title = md.SelectElement("title").Text()
	}

	//reference cve
	var cves []string
	for _, ref := range root.FindElements("//reference") {
		if src := ref.SelectAttr("source"); src != nil {
			if strings.EqualFold(src.Value, "CVE") {

				if refid := ref.SelectAttr("ref_id"); refid != nil {
					cves = append(cves, refid.Value)
				}
			}
		}
	}
	AdvisoryDetails.FixesCVE = append(AdvisoryDetails.FixesCVE, cves...)

	//severity
	if svrty := root.FindElement("//severity"); svrty != nil {
		AdvisoryDetails.Severity = svrty.Text()
	}

	//cpe_list
	var cpes []string
	if cpeList := root.FindElement("//affected_cpe_list"); cpeList != nil {
		for _, cpe := range cpeList.FindElements("cpe") {
			cpes = append(cpes, cpe.Text())
		}
	}

	AdvisoryDetails.AffectedCpe = append(AdvisoryDetails.AffectedCpe, cpes...)

	buildStates(root)
	m := parseCriteria(root)
	AdvisoryDetails.Criteria = m

	rhJSONModel := make(map[string][]interface{})

	rhJSONModel["advisory"] = append(rhJSONModel["advisory"], AdvisoryDetails, Title)

	obj, err := json.Marshal(rhJSONModel)
	check(logger, err)
	fmt.Println(string(obj))
}
