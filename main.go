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
			if arch := rpminfoState.FindElement("arch"); arch != nil {
				if opr := arch.SelectAttr("operation"); opr != nil {
					states[id.Value] = append(states[id.Value], opr.Value)
				}
			}

			if evr := rpminfoState.FindElement("evr"); evr != nil {
				states[id.Value] = append(states[id.Value], evr.Text())
				if dtType := evr.SelectAttr("datatype"); dtType != nil {
					states[id.Value] = append(states[id.Value], dtType.Value)
					if evrOpr := evr.SelectAttr("operation"); evrOpr != nil {
						states[id.Value] = append(states[id.Value], evrOpr.Value)
					}
				}
			}

		}
	}

	for _, rpminfoState := range root.FindElements("//rpmverifyfile_state") {
		if id := rpminfoState.SelectAttr("id"); id != nil {
			states[id.Value] = []string{}
			if name := rpminfoState.FindElement("name"); name != nil {
				if opr := name.SelectAttr("operation"); opr != nil {
					states[id.Value] = append(states[id.Value], opr.Value)
				}
			}

			if ver := rpminfoState.FindElement("version"); ver != nil {
				states[id.Value] = append(states[id.Value], ver.Text())
				if opr := ver.SelectAttr("operation"); opr != nil {
					states[id.Value] = append(states[id.Value], opr.Value)
				}
			}

		}
	}

	fmt.Printf("\n\nBuilding map for states: %s\n\n", states)
	for id, val := range states {
		fmt.Println("id:", id)
		fmt.Println("properties:")
		for _, s := range val {
			fmt.Println("        ", s)
		}
	}
	fmt.Println()

}

func parseCriteria(root *etree.Element) string {

	//walk through the criteria  and when matching the states, insert the state according to id

	return ""
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
	Title := model.Title{}

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
	criterias := parseCriteria(root)
	_ = criterias

	rhJSONModel := make(map[string]interface{})

	rhJSONModel["advisory"] = AdvisoryDetails
	rhJSONModel["title"] = Title

	obj, err := json.Marshal(rhJSONModel)
	check(logger, err)
	fmt.Println(string(obj))
}
