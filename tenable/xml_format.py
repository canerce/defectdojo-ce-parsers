import logging
import re

from cvss import CVSS3
from defusedxml import ElementTree
from hyperlink._url import SCHEME_PORT_MAP

from dojo.models import Endpoint, Finding, Test

LOGGER = logging.getLogger(__name__)


class TenableXMLParser:

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Tenable XML Parser

        Fields:
        - title: Set to plugin name from Tenable scanner.
        - description: Made by combining synopsis element text and plugin output from Tenable Scanner.
        - severity: Set to severity from Tenable Scanner converted to Defect Dojo format.
        - mitigation: Set to solution from Tenable Scanner.
        - impact: Made by combining description element text, cvss score, cvssv3 score, cvss vector, cvss base score, and cvss temporal score from Tenable Scanner.
        - cwe: If present, set to cwe from Tenable scanner.
        - cvssv3: If present, set to cvssv3 from Tenable scanner.
        """
        return [
            "title",
            "description",
            "severity",
            "mitigation",
            "impact",
            "cwe",
            "cvssv3",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of dedupe fields used in the Tenable XML Parser

        Fields:
        - title: Made using the name, plugin name, and asset name from Tenable scanner.
        - severity: Set to severity from Tenable Scanner converted to Defect Dojo format.
        - cwe: If present, set to cwe from Tenable scanner.
        - description: Made by combining synopsis and plugin output from Tenable Scanner.

        NOTE: vulnerability_ids are not provided by parser
        """
        return [
            "title",
            "severity",
            "cwe",
            "description",
        ]

    def get_text_severity(self, severity_id):
        """Convert data of the report into severity"""
        severity = "Info"
        if severity_id == 4:
            severity = "Critical"
        elif severity_id == 3:
            severity = "High"
        elif severity_id == 2:
            severity = "Medium"
        elif severity_id == 1:
            severity = "Low"
        # Ensure the severity is a valid choice. Fall back to info otherwise
        if severity not in Finding.SEVERITIES:
            severity = "Info"
        return severity

    def get_cvss_severity(self, cvss_score):
        """Convert data of the report into severity"""
        severity = "Info"
        if float(cvss_score) >= 9.0:
            severity = "Critical"
        elif float(cvss_score) >= 7.0:
            severity = "High"
        elif float(cvss_score) >= 5.0:
            severity = "Medium"
        elif float(cvss_score) > 0.0:
            severity = "Low"
        else:
            severity = "Info"
        return severity

    def safely_get_element_text(self, element):
        if element is None:
            return None
        if hasattr(element, "text"):
            element_text = element.text
            if element_text is None:
                return None
            if isinstance(element_text, str):
                return element_text if len(element_text) > 0 else None
            if isinstance(element_text, int | float):
                return element_text or None
        return None

    def get_findings(self, filename: str, test: Test) -> list:
        # Read the XML
        nscan = ElementTree.parse(filename)
        root = nscan.getroot()

        if "NessusClientData_v2" not in root.tag:
            msg = (
                "This version of Nessus report is not supported. "
                "Please make sure the export is "
                "formatted using the NessusClientData_v2 schema."
            )
            raise ValueError(msg)

        dupes = {}
        for report in root.iter("Report"):
            for host in report.iter("ReportHost"):
                ip = host.attrib.get("name")
                fqdn = None
                fqdn_element_text = self.safely_get_element_text(
                    host.find('.//HostProperties/tag[@name="host-fqdn"]'),
                )
                if fqdn_element_text is not None:
                    fqdn = fqdn_element_text

                for item in host.iter("ReportItem"):
                    # Set the title
                    title = item.attrib.get("pluginName")
                    # Set the vuln_id_from_tool
                    vuln_id_from_tool = item.attrib.get("pluginID")
                    # Get and clean the port
                    port = None
                    if float(item.attrib.get("port")) > 0:
                        port = item.attrib.get("port")

                    # Get and clean the protocol
                    protocol = str(item.attrib.get("svc_name", ""))
                    if protocol != "":
                        protocol = re.sub(r"[^A-Za-z0-9\-\+]+", "", protocol)
                        if protocol == "www":
                            protocol = "http"
                        if protocol not in SCHEME_PORT_MAP:
                            protocol = re.sub(
                                r"[^A-Za-z0-9\-\+]+",
                                "",
                                item.attrib.get("protocol", protocol),
                            )

                    # Set the description with a few different fields
                    description = ""
                    plugin_output = None
                    synopsis_element_text = self.safely_get_element_text(
                        item.find("synopsis"),
                    )
                    if synopsis_element_text is not None:
                        description = f"{synopsis_element_text}\n\n"
                    description_element_text = self.safely_get_element_text(
                        item.find("description"),
                    )
                    if description_element_text is not None:
                        description += description_element_text + "\n"

                    # Determine the severity
                    nessus_severity_id = int(item.attrib.get("severity", 0))
                    severity = self.get_text_severity(nessus_severity_id)

                    # Build up the impact
                    impact = ""
                    plugin_output_element_text = self.safely_get_element_text(
                        item.find("plugin_output"),
                    )
                    if plugin_output_element_text is not None:
                        plugin_output = f"Plugin Output: {ip}{f':{port}' if port is not None else ''}"
                        plugin_output += f"\n```\n{plugin_output_element_text}\n```"
                        impact = plugin_output

                    # Set the mitigation
                    mitigation = "N/A"
                    mitigation_element_text = self.safely_get_element_text(
                        item.find("solution"),
                    )
                    if mitigation_element_text is not None:
                        mitigation = mitigation_element_text

                    # Build up the references
                    references = ""
                    for ref in item.iter("see_also"):
                        ref_text = self.safely_get_element_text(ref)
                        if ref_text is not None:
                            refs = ref_text.split()
                            for r in refs:
                                references += r + "\n"
                    for xref in item.iter("xref"):
                        xref_text = self.safely_get_element_text(xref)
                        if xref_text is not None:
                            references += xref_text + "\n"

                    vulnerability_id = None
                    cve_element_text = self.safely_get_element_text(
                        item.find("cve"),
                    )
                    if cve_element_text is not None:
                        vulnerability_id = cve_element_text

                    cwe = None
                    cwe_element_text = self.safely_get_element_text(
                        item.find("cwe"),
                    )
                    if cwe_element_text is not None:
                        cwe = cwe_element_text

                    # parsing and storing the CWE would affect dedupe/hash_codes, commentint out for now
                    # if not cwe:
                    #     for ref in item.iter("xref"):
                    #         ref_text = self.safely_get_element_text(ref)
                    #         if ref_text is not None:
                    #             cwe = parse_cwe_from_ref(ref_text)
                    #             if cwe > 0:
                    #                 break

                    cvssv3 = None
                    cvssv3_element_text = self.safely_get_element_text(
                        item.find("cvss3_vector"),
                    )
                    if cvssv3_element_text is not None:
                        if "CVSS:3.0/" not in cvssv3_element_text:
                            cvssv3_element_text = (
                                f"CVSS:3.0/{cvssv3_element_text}"
                            )
                        cvssv3 = CVSS3(cvssv3_element_text).clean_vector(
                            output_prefix=True,
                        )

                    cvssv3_score = None
                    cvssv3_score_element_text = self.safely_get_element_text(
                        item.find("cvssv3"),
                    )
                    if cvssv3_score_element_text is not None:
                        cvssv3_score = cvssv3_score_element_text

                    cvss = self.safely_get_element_text(item.find("cvss3_base_score"))
                    if cvss is not None:
                        severity = self.get_cvss_severity(cvss)

                    # Determine the current entry has already been parsed in
                    # this report
                    if port is not None:
                        dedupe_port = port
                    else:
                        dedupe_port = "0"
                    
                    dupe_key = severity + vuln_id_from_tool + ip + dedupe_port
                    
                    if dupe_key not in dupes:
                        find = Finding(
                            title=title,
                            test=test,
                            description=description,
                            severity=severity,
                            mitigation=mitigation,
                            impact=impact,
                            references=references,
                            cwe=cwe,
                            cvssv3=cvssv3,
                            cvssv3_score=cvssv3_score,
                            vuln_id_from_tool=vuln_id_from_tool,
                        )
                        find.unsaved_endpoints = []
                        find.unsaved_vulnerability_ids = []
                        dupes[dupe_key] = find
                    else:
                        find = dupes[dupe_key]
                        if plugin_output is not None:
                            find.impact += f"\n{plugin_output}"

                    # Update existing vulnerability IDs
                    if vulnerability_id is not None:
                        find.unsaved_vulnerability_ids.append(vulnerability_id)
                    # Create a new endpoint object
                    if fqdn is not None and "://" in fqdn:
                        endpoint = Endpoint.from_uri(fqdn)
                    elif protocol == "general":
                        endpoint = Endpoint(host=ip or fqdn)
                    else:
                        endpoint = Endpoint(
                            protocol=protocol,
                            host=ip or fqdn,
                            port=port,
                        )
                    find.unsaved_endpoints.append(endpoint)

        return list(dupes.values())