
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

2. Known Vulnerabilities not shown in Burp UI

 Issues of type "Known Vulnerabilities" are not currently shown in the BURP user interface.
 To view these issues, access the Peach API Security web UI.

## Installation

This extension has been submitted to the BApp marketplace. Once accepted it can
be installed through the Burp user interface.

## Usage

### Configuration

Goto the Peach API Security tab in Burp, the Settings sub-tab should be visable as shown below.

![settings](https://github.com/PeachTech/peachapisec-burp/raw/master/images/settings.png)

Fill in the settings based on your deployment of Peach API Security. The API Token can be found on the Peach API Security Settings page.

Once you have filled in the settings, click the "Test Connection" button to verify
correct connectivity. If you do not have a valid SSL certificate installed, please use
the "http" protocol instead of "https" for testing.

### Perform testing

To start a Peach API Security test, follow these steps:

1. Record some traffic in Burp

  The Target -> Site Map tab should have one or more endpoints shown.

2. Right click on an item in the site map you want to test

  If the item has children, for example right-clicking on an endpoint, all of the sub
  requests will be tested.

3. Select the "Test with Peach API Security" menu item

  ![start test](https://github.com/PeachTech/peachapisec-burp/raw/master/images/testwithpeachapi.png)

4. View the testing status

  To view the testing status, click on the Peach API Security tab, a sub-tab "Status" will
  be shown.  This will show the current status of the test, and how many estimated tests are
  left. The estimated number of tests will grow as testing is performed.

  ![test status](https://github.com/PeachTech/peachapisec-burp/raw/master/images/teststatus.png)

### Viewing Results

  There are three ways to view results of a test:

  * Via the Target -> Site Map view
  * Via the Scanner -> Issue Activity tab
  * Via the Peach API Security UI

#### Viewing Restuls in Target -> Site Map

  Any issues found are viewable in the Target -> Site Map view of Burp.
  They appear in the Issues section as shown in the following image:

  ![results](https://github.com/PeachTech/peachapisec-burp/raw/master/images/sitemapresults.png)

#### Viewing Results in Scanner -> Issue Activity tab

  Any issues found are viewable in the Scanner -> Issue Activity tab as
  shown in the following image:

  ![results](https://github.com/PeachTech/peachapisec-burp/raw/master/images/scannerresults.png)

#### Request/Response Pairs Attached to Issues

Each reported issue will have several request/response pairs provided.

* Request 1 -- This is actual request with any test modifications
* Request 2 -- This is origional request with out test modifications
* Request 3 -- This is an example of a correct request/response pair

![results](https://github.com/PeachTech/peachapisec-burp/raw/master/images/scannerresults.png)

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
