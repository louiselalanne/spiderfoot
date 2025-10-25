# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_tool_nuclei
# Purpose:      SpiderFoot plug-in for using the 'Nuclei' tool.
#               Tool: https://github.com/EnableSecurity/nuclei
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     2022-04-02
# Copyright:   (c) Steve Micallef 2022
# Licence:     MIT
# -------------------------------------------------------------------------------

import os
import re
import sys
import json
from netaddr import IPNetwork
from subprocess import Popen, PIPE, TimeoutExpired

from spiderfoot import SpiderFootPlugin, SpiderFootEvent, SpiderFootHelpers


class sfp_tool_nuclei(SpiderFootPlugin):

    meta = {
        "name": "Tool - Nuclei",
        "summary": "Fast and customisable vulnerability scanner.",
        "flags": [
            "tool",
            "slow",
            "invasive"
        ],
        "useCases": [
            "Footprint",
            "Investigate"
        ],
        "categories": ["Crawling and Scanning"],
        "toolDetails": {
            "name": "Nuclei",
            "description": "Fast and customisable vulnerability scanner based on simple YAML based DSL.",
            "website": "https://nuclei.projectdiscovery.io/",
            "repository": "https://github.com/projectdiscovery/nuclei"
        }
    }

    opts = {
        "nuclei_path": "",
        "template_path": "",
        'netblockscan': True,
        'netblockscanmax': 24
    }

    optdescs = {
        'nuclei_path': "The path to your nuclei binary. Must be set.",
        'template_path': "The path to your nuclei templates. Must be set.",
        'netblockscan': "Check all IPs within identified owned netblocks?",
        'netblockscanmax': "Maximum netblock/subnet size to scan IPs within (CIDR value, 24 = /24, 16 = /16, etc.)"
    }

    # Target
    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["INTERNET_NAME", "IP_ADDRESS", "NETBLOCK_OWNER"]

    def producedEvents(self):
        return [
            "VULNERABILITY_CVE_CRITICAL",
            "VULNERABILITY_CVE_HIGH",
            "VULNERABILITY_CVE_MEDIUM",
            "VULNERABILITY_CVE_LOW",
            "IP_ADDRESS",
            "VULNERABILITY_GENERAL",
            "WEBSERVER_TECHNOLOGY"
        ]

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.errorState:
            return

        if srcModuleName == "sfp_tool_nuclei":
            return

        if not self.opts['nuclei_path'] or not self.opts['template_path']:
            self.error("You enabled sfp_tool_nuclei but did not set a path to the tool and/or templates!")
            self.errorState = True
            return

        exe = self.opts['nuclei_path']
        if self.opts['nuclei_path'].endswith('/'):
            exe = f"{exe}nuclei"

        if not os.path.isfile(exe):
            self.error(f"File does not exist: {exe}")
            self.errorState = True
            return

        if not SpiderFootHelpers.sanitiseInput(eventData, extra=['/']):
            self.debug("Invalid input, skipping.")
            return
        if eventData in self.results:
            self.debug(f"Skipping {eventData} as already scanned.")
            return

        if eventName != "INTERNET_NAME":
            for addr in self.results:
                try:
                    if IPNetwork(eventData) in IPNetwork(addr):
                        self.debug(f"Skipping {eventData} as already within a scanned range.")
                        return
                except BaseException:
                    continue

        self.results[eventData] = True

        timeout = 240
        try:
            target = eventData
            if eventName == "NETBLOCK_OWNER" and self.opts['netblockscan']:
                target = ""
                net = IPNetwork(eventData)
                if net.prefixlen < self.opts['netblockscanmax']:
                    self.debug(f"Skipping scanning of {eventData}, too big.")
                    return

                for addr in IPNetwork(eventData).iter_hosts():
                    target += str(addr) + "\n"
                    timeout += 240
        except BaseException as e:
            self.error(f"Strange netblock identified, unable to parse: {eventData} ({e})")
            return

        try:
            args = [
                exe,
                "-silent",
                "-jsonl",
                "-concurrency",
                "100",
                "-retries",
                "1",
                "-t",
                self.opts["template_path"],
                "-no-interactsh",
                "-etags",
                "dos",
                "fuzz",
                "misc",
            ]
            p = Popen(args, stdin=PIPE, stdout=PIPE, stderr=PIPE)
            try:
                stdout, stderr = p.communicate(input=target.encode(sys.stdin.encoding), timeout=timeout)
                if p.returncode == 0:
                    content = stdout.decode(sys.stdout.encoding)
                else:
                    self.error("Unable to read Nuclei content.")
                    self.debug(f"Error running Nuclei: {stderr}, {stdout}")
                    return
            except TimeoutExpired:
                p.kill()
                stdout, stderr = p.communicate()
                self.debug("Timed out waiting for Nuclei to finish")
                return
        except BaseException as e:
            self.error(f"Unable to run Nuclei: {e}")
            return

        if not content:
            return

        for line in content.split("\n"):
            if not line.strip():
                continue
            
            if not line.strip().startswith('{'):
                continue
                
            try:
                data = json.loads(line)
                
                if 'matched-at' not in data or 'info' not in data:
                    continue
                
                srcevent = event
                matched_url = data.get('matched-at', '')
                if matched_url:
                    if matched_url.startswith('http'):
                        from urllib.parse import urlparse
                        parsed = urlparse(matched_url)
                        host = parsed.hostname
                    else:
                        host = data.get('host', eventData)
                else:
                    host = data.get('host', eventData)
                
                if host and host != eventData:
                    if self.sf.validIP(host):
                        srctype = "IP_ADDRESS"
                    else:
                        srctype = "INTERNET_NAME"
                    srcevent = SpiderFootEvent(srctype, host, self.__name__, event)
                    self.notifyListeners(srcevent)


                template_info = data.get('info', {})
                cve_list = []
                
                classification = template_info.get('classification', {})
                if classification.get('cve-id'):
                    cve_id = classification.get('cve-id')
                    if isinstance(cve_id, list):
                        cve_list.extend(cve_id)
                    elif isinstance(cve_id, str):
                        cve_list.append(cve_id)
                
                template_id = data.get('template-id', '')
                if 'CVE-' in template_id:
                    matches = re.findall(r"CVE-\d{4}-\d{4,7}", template_id)
                    cve_list.extend(matches)
                
                if cve_list:
                    for cve in cve_list:
                        if cve and cve != 'null':
                            etype, cvetext = self.sf.cveInfo(cve)
                            e = SpiderFootEvent(etype, cvetext, self.__name__, srcevent)
                            self.notifyListeners(e)
                else:
                    severity = template_info.get('severity', 'info').lower()
                    
                    if severity == "info":
                        etype = "WEBSERVER_TECHNOLOGY"
                    else:
                        etype = "VULNERABILITY_GENERAL"
                    
                    datatext = f"Template: {template_info.get('name', 'Unknown')} ({data.get('template-id', 'Unknown')})\n"
                    
                    if data.get('matcher-name'):
                        datatext += f"Matcher: {data.get('matcher-name')}\n"
                    
                    if data.get('matched-at'):
                        datatext += f"Matched at: {data.get('matched-at')}\n"
                    
                    if severity != 'info':
                        datatext += f"Severity: {severity}\n"
                    
                    if template_info.get('description'):
                        datatext += f"Description: {template_info.get('description')}\n"
                    
                    references = template_info.get('reference', [])
                    if references:
                        if isinstance(references, list) and len(references) > 0:
                            datatext += f"Reference: <SFURL>{references[0]}</SFURL>"
                        elif isinstance(references, str):
                            datatext += f"Reference: <SFURL>{references}</SFURL>"
                    
                    evt = SpiderFootEvent(etype, datatext, self.__name__, srcevent)
                    self.notifyListeners(evt)
                    
            except json.JSONDecodeError as e:
                self.debug(f"Skipping non-JSON line: {line}")
                continue
            except KeyError as e:
                self.debug(f"Missing expected key in Nuclei output: {e}")
                continue

# End of sfp_tool_nuclei class
