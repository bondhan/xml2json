package main

import (
	// "io/ioutil"

	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"

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

	xmlFile, err := os.Open("file/input.xml")
	// if we os.Open returns an error then handle it
	if err != nil {
		logger.Log("Error", err)
	}
	defer xmlFile.Close()

	byteValue, _ := ioutil.ReadAll(xmlFile)

	// we initialize our Users array
	var oval model.Oval
	err = xml.Unmarshal(byteValue, &oval)
	if err != nil {
		logger.Log("Error", err)
	}

	// m, err := json.Marshal(oval)
	// if err != nil {
	// 	logger.Log("Error", err)
	// }
	// fmt.Printf("\n\nResult: \n%s\n", m)

	var cves []string
	for _, ref := range oval.Definitions.Definition.Metadata.Reference {
		cves = append(cves, ref.RefID)
	}

	var affected []string
	for _, aff := range oval.Definitions.Definition.Metadata.Affected.Platform {
		affected = append(affected, aff)
	}

	// var advisory model.Advisory
	advisoryDetails := model.AdvisoryDetails{
		Title:       oval.Definitions.Definition.Metadata.Title,
		FixesCVE:    cves,
		Severity:    oval.Definitions.Definition.Metadata.Advisory.Severity,
		AffectedCpe: affected,
	}

	adT := model.AdTitle{
		Title: "...",
	}

	da := model.DataAdvisory{
		AdvisoryDetails: advisoryDetails,
		AdTitle:         adT,
	}

	root := model.Advisory{
		Dataadvisory: []model.DataAdvisory{da},
	}

	res, err := json.Marshal(&root)
	if err != nil {
		logger.Log("Error", err)
	}
	fmt.Printf("\n\nResult: \n%s\n", res)

}
