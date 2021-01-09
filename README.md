# xml2json

## Explanation of general algorithm

1. Create the the correct JSON model accordingly to the reference.json (see file/reference.json)
2. Walk through the xmls file (file/input.xml) to get:
    - title
    - fixes_cve
    - severity
    - affected_cpe
    - titles 
    - then insert each to json model
3. For criteria:
    - build repo for objects from tag `<objects>`
    - build repo for states from tag `<states>`
    - build repo for tag`<tests>` from previous step objects and states
    - walk through criteria and criterion, when id match tests repo then replace with the tests value
    - insert to json model
4. Got the final json model then marshall it we will get final json

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
