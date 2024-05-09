import re
from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from burp import ITab
from array import array
from java.io import PrintWriter
from javax.swing import JPanel, JCheckBox, BoxLayout

EXT_NAME = "PII - CPFs Challenge"

class BurpExtender(IBurpExtender, IScannerCheck, ITab):
    def __init__(self):
        self.cpf_regex = r'\b(?:\d{3}\.?\d{3}\.?\d{3}-?\d{2})\b'

    def registerExtenderCallbacks(self, callbacks):
        callbacks.setExtensionName(EXT_NAME)
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout = PrintWriter(callbacks.getStdout(), True)  # Inicialize self._stdout aqui
        callbacks.registerScannerCheck(self)
        callbacks.addSuiteTab(self)

    def doPassiveScan(self, baseRequestResponse):
        response = baseRequestResponse.getResponse()
        matches = re.findall(self.cpf_regex, self._helpers.bytesToString(response))
        if matches:
            self._stdout.println("CPF found: {}".format(matches[0]))
            return [CustomScanIssue(baseRequestResponse.getHttpService(), self._helpers.analyzeRequest(baseRequestResponse).getUrl(), [baseRequestResponse], "CPF Detected", "CPF detected in response", "High")]
        return None

    def getUiComponent(self):
        self.panel = JPanel()
        self.panel.setLayout(BoxLayout(self.panel, BoxLayout.Y_AXIS))

        self.checkbox = JCheckBox("Detect CPFs")
        self.checkbox.setSelected(True)
        self.panel.add(self.checkbox)

        return self.panel

    def getTabCaption(self):
        return EXT_NAME

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1
        return 0

    def extensionUnloaded(self):
        self._stdout.println("Extension was unloaded")

class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
