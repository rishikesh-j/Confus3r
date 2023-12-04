#Confus3r
#Author: Rishikesh J

from burp import IBurpExtender
from burp import IScanIssue
from burp import IScannerCheck
import json
import urllib2

class BurpExtender(IBurpExtender, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Confus3r: Dependency Checker")
        callbacks.registerScannerCheck(self)
        callbacks.issueAlert("Registered Dependency Checker...")
        print("Dependency Checker extension loaded.")
        return

    def getResponseHeadersAndBody(self, content):
        response = content.getResponse()
        response_data = self._helpers.analyzeResponse(response)
        headers = list(response_data.getHeaders())
        body = response[response_data.getBodyOffset():].tostring()
        return headers, body

    def check_npm_registry(self, registry):
        missing_dependencies = []

        try:
            registry_url = "https://unpkg.com/{}".format(registry)
            response = urllib2.urlopen(registry_url)

            if response.getcode() != 200:
                missing_dependencies.append(registry)

        except urllib2.URLError as e:
            missing_dependencies.append(registry)
            print("Error checking npm registry for {}: {}".format(registry, e))

        return missing_dependencies

    def doPassiveScan(self, baseRequestResponse):
        issues = []
        headers, body = self.getResponseHeadersAndBody(baseRequestResponse)

        # Check if the response body contains composer.json
        if "package.json" in baseRequestResponse.getUrl().toString():
            # Get the response content
            response = self._helpers.bytesToString(baseRequestResponse.getResponse())

            # Extract JSON content from the response
            json_start = response.find("{")
            json_end = response.rfind("}")
            json_content = response[json_start:json_end + 1]

            try:
                # Try to parse the extracted JSON content
                json_data = json.loads(json_content)

                # Check if the "dependencies" key exists in the parsed JSON
                if "dependencies" in json_data and isinstance(json_data["dependencies"], dict):
                    npm_registries = json_data["dependencies"].keys()
                    print(npm_registries)

                    missing_dependencies = []
                    for registry in npm_registries:
                        missing_dependencies.extend(self.check_npm_registry(registry))

                    if missing_dependencies:
						self._callbacks.issueAlert("Missing dependencies in npm registry. Check Issue Activity!")
						self._callbacks.printOutput("Missing dependencies in npm registry. Check Issue Activity!")
						# Report the issue
						issues.append(NpmRegistryScanIssue(
							baseRequestResponse.getHttpService(),
							self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
							[baseRequestResponse],
							missing_dependencies
						))

                else:
                    print("'dependencies' key not found or is not a dictionary in JSON")

            except json.JSONDecodeError as e:
                print("Error decoding JSON: {}".format(e))

        if not issues:
            issues = None

        return issues

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        pass

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1
        return 0

class NpmRegistryScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, missing_dependencies):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._missing_dependencies = missing_dependencies

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return "Dependency Confusion (NPM)"

    def getSeverity(self):
        return "High"

    def getConfidence(self):
        return "Certain"

    def getIssueDetail(self):
        missing_dependencies_str = ', '.join(self._missing_dependencies)
        return "The following dependencies are missing in the npm registry: {}".format(missing_dependencies_str)

    def getRemediationBackground(self):
    	return

    def getRemediationDetail(self):
    	return

    def getIssueBackground(self):
    	return "A dependency confusion attack is a type of supply chain attack that occurs when an attacker publishes a malicious package to a public package registry, such as the npm registry for Node.js packages. The goal of the attacker is to trick developers into unknowingly installing and using the malicious package by exploiting the way package managers handle dependencies."

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
