package main

import (
	// "io/ioutil"

	"encoding/json"
	"fmt"
	"os"
	"strings"

	// xj "github.com/basgys/goxml2json"

	"github.com/beevik/etree"
	"github.com/bondhan/xml2json/model"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
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

	// fs := flag.NewFlagSet("xml", flag.ExitOnError)
	// xmlInput := fs.String("url", "https://www.redhat.com/security/data/oval/com.redhat.rhsa-20130696.xml", "xml url")

	// if len(os.Args) >= 2 {
	// 	fs.Parse(os.Args[2:])
	// } else {
	// 	logger.Log("Info", "No URL specified, downloading default https://www.redhat.com/security/data/oval/com.redhat.rhsa-20130696.xml")
	// }

	// resp, err := http.Get(*xmlInput)
	// if err != nil {
	// 	logger.Log("Error", err)
	// 	os.Exit(-1)
	// }
	// defer resp.Body.Close()

	// // Create the file
	// out, err := os.Create("file/input.xml")
	// if err != nil {
	// 	logger.Log("Error", err)
	// 	os.Exit(-1)
	// }
	// defer out.Close()

	// // Write the body to file
	// _, err = io.Copy(out, resp.Body)
	// if err != nil {
	// 	logger.Log("Error", err)
	// 	os.Exit(-1)
	// }

	// bodyBytes, err := ioutil.ReadAll(resp.Body) //<--- here!

	// if err != nil {
	// 	fmt.Println(err)
	// 	os.Exit(1)
	// }

	// print out
	// fmt.Println(os.Stdout, string(xmlData)) //<-- here !

	// //proses the file
	// xml := strings.NewReader(string(xmlData))
	// json, err := xj.Convert(xml)
	// if err != nil {
	// 	panic("That's embarrassing...")
	// }

	// fmt.Println(json.String())

	// dat, err := ioutil.ReadFile("file/input.xml")
	// check(logger, err)

	doc := etree.NewDocument()
	if err := doc.ReadFromFile("file/input.xml"); err != nil {
		panic(err)
	}

	// //proses the file
	// xml := strings.NewReader(string(dat))
	// json, err := xj.Convert(xml)
	// if err != nil {
	// 	panic("That's embarrassing...")
	// }

	// fmt.Println(json.String())

	rhJSONModels := model.JSONRhModels{}
	advisoryMids := []model.AdvisoryMid{}

	advisoryMid := model.AdvisoryMid{}

	root := doc.SelectElement("oval_definitions")

	//title
	for _, md := range root.FindElements("//metadata") {
		advisoryMid.AdvisoryMid.Title = md.SelectElement("title").Text()
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
	advisoryMid.AdvisoryMid.FixesCVE = append(advisoryMid.AdvisoryMid.FixesCVE, cves...)

	//severity
	if svrty := root.FindElement("//severity"); svrty != nil {
		advisoryMid.AdvisoryMid.Severity = svrty.Text()
	}

	//cpe_list
	var cpes []string
	if cpeList := root.FindElement("//affected_cpe_list"); cpeList != nil {
		for _, cpe := range cpeList.FindElements("cpe") {
			cpes = append(cpes, cpe.Text())
		}
	}

	advisoryMid.AdvisoryMid.AffectedCpe = append(advisoryMid.AdvisoryMid.AffectedCpe, cpes...)

	advisoryMids = append(advisoryMids, advisoryMid)
	rhJSONModels.Advisory = advisoryMids

	obj, err := json.Marshal(rhJSONModels)
	check(logger, err)
	fmt.Println(string(obj))
}
