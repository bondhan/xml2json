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
    - build repo for objects from <objects>
    - build repo for states from <states>
    - build repo for <tests> from previous objects and states
    - walk through criteria and criterion, when id match tests repo then replace with the tests value
    - insert to json model
4. Got the final json model then marshall it we will get final json

## output (unfinished)
```json
{"advisory":[{"title":"RHSA-2013:0696: firefox security update (Critical)","fixes_cve":["CVE-2013-0788","CVE-2013-0793","CVE-2013-0795","CVE-2013-0796","CVE-2013-0800"],"severity":"Critical","affected_cpe":["cpe:/o:redhat:enterprise_linux:5","cpe:/o:redhat:enterprise_linux:6","cpe:/o:redhat:enterprise_linux:5::client","cpe:/o:redhat:enterprise_linux:5::client_workstation","cpe:/o:redhat:enterprise_linux:5::server","cpe:/o:redhat:enterprise_linux:6::workstation","cpe:/o:redhat:enterprise_linux:6::computenode","cpe:/o:redhat:enterprise_linux:6::client","cpe:/o:redhat:enterprise_linux:6::server"],"criteria":[]},{"title":"..."}]}
```
