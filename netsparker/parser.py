import datetime
import json
import html2text
from cvss import CVSS3
from cvss import parser as cvss_parser
from dateutil import parser as date_parser
from urllib.parse import urlparse

from dojo.models import Endpoint, Finding


class NetsparkerParser:
    def get_scan_types(self):
        return ["Netsparker Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Netsparker Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Netsparker JSON format."

    def get_findings(self, filename, test):
        tree = filename.read()        
        try:
            data = json.loads(str(tree, "utf-8-sig"))
        except Exception:
            data = json.loads(tree)
        dupes = {}
        try:
            if "UTC" in data["Generated"]:
                scan_date = datetime.datetime.strptime(
                    data["Generated"].split(" ")[0], "%d/%m/%Y",
                ).date()
            else:
                scan_date = datetime.datetime.strptime(
                    data["Generated"], "%d/%m/%Y %H:%M %p",
                ).date()
        except ValueError:
            try:
                scan_date = date_parser.parse(data["Generated"])
            except date_parser.ParserError:
                scan_date = None
        target_url = data.get("Target", {}).get("Url", "")
        test_fqdn = urlparse(target_url).hostname
        if test_fqdn:
            test.title = test_fqdn
            test.save()
        for item in data["Vulnerabilities"]:
            h = html2text.HTML2Text()
            h.body_width = 0
            h.strong_mark = ""
            h.emphasis_mark = ""
            h.single_line_break = True
            title = item["Name"]
            url = urlparse(item["Url"])
            sev = item["Severity"]
            scanner_confidence = item["Certainty"]
            unique_id_from_tool = item["LookupId"]
            if sev not in {"Info", "Low", "Medium", "High", "Critical"}:
                sev = "Info"
            
            if "Cwe" in item["Classification"]:
                try:
                    cwe = int(item["Classification"]["Cwe"].split(",")[0])
                except Exception:
                    cwe = None
            else:
                cwe = None
            
            issueDescription = item.get("Description", "")
            issueImpact = item.get("Impact", "")
            if len(issueImpact) > 0:
                issueImpact = "<br>" + issueImpact
            description = h.handle(issueDescription + issueImpact)
            
            remedialProcedure = item.get("RemedialProcedure", "")
            remedialActions = item.get("RemedialActions", "")
            if len(remedialActions) > 0:
                remedialActions = "<br>" + remedialActions
            mitigation = h.handle(remedialProcedure + remedialActions)
            
            externalReferences = item.get("ExternalReferences", "")
            remedyReferences = item.get("RemedyReferences", "")
            references = h.handle(externalReferences + remedyReferences)
            
            impact = ""
            extraInformation = item.get("ExtraInformation", None)
            if len(extraInformation) > 0:
                for information in extraInformation:
                    if len(impact) > 0:
                        impact += "\n"
                    impact += "{0}:\n{1}".format(information["Name"], information["Value"].replace(", ", "\n"))
            impact += f"\n{url.geturl()}"
            dupe_key = title + sev + unique_id_from_tool
            request = item["HttpRequest"].get("Content", None)
            response = item["HttpResponse"].get("Content", None)

            finding = Finding(
                title=title,
                test=test,
                description=description,
                severity=sev.title(),
                mitigation=mitigation,
                impact=impact,
                date=scan_date,
                references=references,
                cwe=cwe,
                static_finding=True,
                unique_id_from_tool=unique_id_from_tool,
                scanner_confidence=scanner_confidence,
            )
            state = item.get("State", None)
            if state == "FalsePositive":
                finding.active = False
                finding.verified = False
                finding.false_p = True
                finding.mitigated = None
                finding.is_mitigated = False
            elif state == "AcceptedRisk":
                finding.risk_accepted = True

            verifystatus = item.get("Confirmed", None)
            if not verifystatus:
                finding.verified = False
            if item["Classification"] is not None:
                if item["Classification"].get("Cvss") is not None and item["Classification"].get("Cvss").get("Vector") is not None:
                    cvss_objects = cvss_parser.parse_cvss_from_text(
                        item["Classification"]["Cvss"]["Vector"],
                    )
                    if len(cvss_objects) > 0:
                        finding.cvssv3 = cvss_objects[0].clean_vector()
                    if item["Classification"].get("Cvss").get("BaseScore") is not None:
                        finding.cvssv3_score = item["Classification"].get("Cvss").get("BaseScore").get("Value")
                elif item["Classification"].get("Cvss31") is not None and item["Classification"].get("Cvss31").get("Vector") is not None:
                    cvss_objects = cvss_parser.parse_cvss_from_text(
                        item["Classification"]["Cvss31"]["Vector"],
                    )
                    if len(cvss_objects) > 0:
                        finding.cvssv3 = cvss_objects[0].clean_vector()
                    if item["Classification"].get("Cvss31").get("BaseScore") is not None:
                        finding.cvssv3_score = item["Classification"].get("Cvss31").get("BaseScore").get("Value")
            finding.unsaved_req_resp = [{"req": str(request), "resp": str(response)}]
            finding.unsaved_endpoints = [Endpoint(protocol=url.scheme,host=url.hostname)]

            if dupe_key in dupes:
                find = dupes[dupe_key]
                find.unsaved_req_resp.extend(finding.unsaved_req_resp)
                find.unsaved_endpoints.extend(finding.unsaved_endpoints)
            else:
                dupes[dupe_key] = finding
            
            h.close()

        return list(dupes.values())