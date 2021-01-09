# xml2json

## Explanation of general algorithm

1. Create the first model based on oval http://oval.mitre.org/XMLSchema
2. Read the xml file and unmarshal to object
3. Create second model based on "file/reference.json"
4. Manipulate and parse the result from first model to second model

## output (unfinished)
```json
{"advisory":[{"advisory":{"title":"RHSA-2013:0696: firefox security update (Critical)","fixes_cve":["RHSA-2013:0696","CVE-2013-0788","CVE-2013-0793","CVE-2013-0795","CVE-2013-0796","CVE-2013-0800"],"severity":"Critical","affected_cpe":["Red Hat Enterprise Linux 5","Red Hat Enterprise Linux 6"],"criteria":null},"title":"..."}]}
```

## usage
go run main.go xml -url "https://www.redhat.com/security/data/oval/com.redhat.rhsa-20130696.xml"

<pre>
Usage of xml:
  -url string
        xml url (default "https://www.redhat.com/security/data/oval/com.redhat.rhsa-20130696.xml")
</pre>
