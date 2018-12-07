
# Peach API Security Burp Extension
![build status](https://travis-ci.org/PeachTech/peachapisec-burp.svg?branch=master)

This Burp plugin provides integration between Burp and [Peach API Security](https://peach.tech).
A license and existing deployment of Peach API Security is required for use.

[Peach API Security](https://peach.tech) is an automated security testing solution that allows organizations to test their web APIs against the OWASP Top-10 and PCI Section 6.5. Integrating Peach API Security into your existing Continuous Integration (CI) system ensures that your product development teams receive immediate feedback on the security of your latest release. Organizations use Peach API Security to reveal and correct vulnerabilities in their web APIs.

If you would like more information about [Peach API Security](https://peach.tech), please contact our sales team at sales@peach.tech.

## Current features

* Perform tests from Burp UI
* Test results populated as Burp scan issues

## Known Limitations or Issues

1. Peach API Security tab not highlighted while scan is running

 After starting a scan from the Target tab in the Burp UI, a scan
 progress is shown on the Peach API Security tab in the Burp UI.
 Due to a limitation of the Burp API, the tab is currently not highlighted.

1. Known Vulnerabilities not shown in Burp UI

 Issues of type "Known Vulnerabilities" are not currently shown in the BURP user interface.
 To view these issues, access the Peach API Security web UI.

## License

Copyright 2018 Peach Tech

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
