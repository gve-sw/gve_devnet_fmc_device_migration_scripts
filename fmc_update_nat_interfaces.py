"""
Copyright (c) 2022 Cisco and/or its affiliates.
This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at
               https://developer.cisco.com/docs/licenses

All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.
"""

import json
import sys

import requests
import yaml
from requests.api import get, post, put
from requests.auth import HTTPBasicAuth
from requests.models import Response
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm
from time import sleep

console = Console()

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

#######################
# Set FMC details & login credentials:
USERNAME = ""
PASSWORD = ""
FMC = ""

# Set Target NAT policy to edit:
TARGET_NAT_POLICY = ""

# Mapping file:
NAT_INTERFACE_MAP = ""
#######################

PLATFORM_URL = "https://" + FMC + "/api/fmc_platform/v1"
CONFIG_URL = "https://" + FMC + "/api/fmc_config/v1"


# Load NAT interface mapping from config YAML
with open(NAT_INTERFACE_MAP) as config:
    try:
        nat_map = yaml.safe_load(config)
    except yaml.YAMLError as e:
        console.print(f"[red][bold]Error loading {NAT_INTERFACE_MAP}: {e}")
        sys.exit(1)


class FirePower:
    def __init__(self):
        """
        Initialize the FirePower class, log in to FMC,
        and save authentication headers
        """
        with requests.Session() as self.s:
            console.print(f"Attempting login to {FMC}")
            self.authRequest()

            self.headers = {
                "Content-Type": "application/json",
                "X-auth-access-token": self.token,
            }

    def authRequest(self):
        """
        Authenticate to FMC and retrieve auth token
        """
        authurl = f"{PLATFORM_URL}/auth/generatetoken"
        resp = self.s.post(authurl, auth=(USERNAME, PASSWORD), verify=False)
        if resp.status_code == 204:
            # API token, Refresh token, default domain, and
            # other info returned in HTTP headers
            console.print("[green][bold]Connected to FMC.")
            # Save auth token & global domain UUID
            self.token = resp.headers["X-auth-access-token"]
            self.global_UUID = resp.headers["DOMAIN_UUID"]
            console.print(f"\nGlobal domain UUID: {self.global_UUID}")
            return
        else:
            console.print("[red]Authentication Failed.")
            console.print(resp.text)
            sys.exit(1)

    def getInterfaceGroups(self):
        """
        Look up all interface groups from FMC & save their name-to-UUID mapping
        """
        url = f"{CONFIG_URL}/domain/{self.global_UUID}/object/interfacegroups?limit=1000"
        console.print("Querying FMC for all configured interface groups...")
        resp = self.getData(url)
        self.interface_groups = {}
        if resp:
            resp_json = json.loads(resp)
            for intgrp in resp_json["items"]:
                self.interface_groups[intgrp["name"]] = intgrp["id"]
        console.print(f"Saved UUIDs for {len(self.interface_groups)} interface groups.")

    def getNATPolicyUUID(self):
        """
        Retrieve NAT policy UUID by name
        """
        url = f"{CONFIG_URL}/domain/{self.global_UUID}/policy/ftdnatpolicies"
        console.print("Querying FMC for NAT policies...")
        resp = self.getData(url)
        if resp:
            resp_json = json.loads(resp)
            for obj in resp_json["items"]:
                if obj["name"] == TARGET_NAT_POLICY:
                    console.print(
                        f"Found UUID for NAT policy {TARGET_NAT_POLICY}: {obj['id']}"
                    )
                    self.nat_policy_id = obj["id"]
                    return
            # If UUID not found:
            console.print(
                f"[red]Could not find UUID for NAT policy: {TARGET_NAT_POLICY}"
            )
            sys.exit(1)
        else:
            console.print(
                f"[red]Could not find UUID for NAT policy: {TARGET_NAT_POLICY}"
            )
            sys.exit(1)

    def getNATRules(self, ruletype):
        """
        Query all NAT rules for given NAT policy UUID & type
        """
        url = f"{CONFIG_URL}/domain/{self.global_UUID}/policy/ftdnatpolicies/{self.nat_policy_id}/{ruletype}natrules?expanded=True"
        resp = self.getData(url)
        if ruletype == "manual":
            self.manual_nat_rules = []
        if ruletype == "auto":
            self.auto_nat_rules = []
        if resp:
            resp_json = json.loads(resp)
            console.print(
                f"FMC returned {resp_json['paging']['count']} {ruletype}-NAT Rules."
            )
            console.print(f"\nProcessing output...")
            if ruletype == "manual":
                self.manual_nat_rules = resp_json["items"]
            if ruletype == "auto":
                self.auto_nat_rules = resp_json["items"]
        console.print(f"Saved {len(self.auto_nat_rules)} {ruletype}-NAT entries")

    def processNATRules(self):
        """
        Updates NAT source & destination interfaces based on provided mapping table
        """
        console.print("Beginning local update of NAT rules using interace mapping...")
        # Update Manual NAT interface groups
        index = 0
        for entry in self.manual_nat_rules:
            del self.manual_nat_rules[index]["metadata"]
            del self.manual_nat_rules[index]["links"]
            if entry["sourceInterface"]["name"] in nat_map:
                src_int = entry["sourceInterface"]["name"]
                new_src_int = nat_map[src_int]
                self.manual_nat_rules[index]["sourceInterface"]["name"] = new_src_int
                self.manual_nat_rules[index]["sourceInterface"][
                    "id"
                ] = self.interface_groups[new_src_int]
            if entry["destinationInterface"]["name"] in nat_map:
                dst_int = entry["destinationInterface"]["name"]
                new_dst_int = nat_map[dst_int]
                self.manual_nat_rules[index]["destinationInterface"][
                    "name"
                ] = new_dst_int
                self.manual_nat_rules[index]["destinationInterface"][
                    "id"
                ] = self.interface_groups[new_dst_int]
            index += 1
        console.print(f"[green][bold]Updated {index} Manual-NAT rules.")

        # Update Auto NAT interface groups
        index = 0
        for entry in self.auto_nat_rules:
            del self.auto_nat_rules[index]["metadata"]
            del self.auto_nat_rules[index]["links"]
            if entry["sourceInterface"]["name"] in nat_map:
                src_int = entry["sourceInterface"]["name"]
                new_src_int = nat_map[src_int]
                self.auto_nat_rules[index]["sourceInterface"]["name"] = new_src_int
                self.auto_nat_rules[index]["sourceInterface"][
                    "id"
                ] = self.interface_groups[new_src_int]
            if entry["destinationInterface"]["name"] in nat_map:
                dst_int = entry["destinationInterface"]["name"]
                new_dst_int = nat_map[dst_int]
                self.auto_nat_rules[index]["destinationInterface"]["name"] = new_dst_int
                self.auto_nat_rules[index]["destinationInterface"][
                    "id"
                ] = self.interface_groups[new_dst_int]
            index += 1
        console.print(f"[green][bold]Updated {index} Auto-NAT rules.")

    def updateNATRules(self, ruletype):
        """
        Sends updated NAT policies to FMC for provided type
        """
        if ruletype == "manual":
            for entry in self.manual_nat_rules:
                url = f"{CONFIG_URL}/domain/{self.global_UUID}/policy/ftdnatpolicies/{self.nat_policy_id}/manualnatrules/{entry['id']}"
                resp = self.putData(url, entry)
                if resp:
                    console.print(
                        f"[green][bold]Updated NAT entry ID {entry['id']} successfully."
                    )
                # FMC rate limit is 120 requests per minute
                sleep(0.55)

        if ruletype == "auto":
            for entry in self.auto_nat_rules:
                url = f"{CONFIG_URL}/domain/{self.global_UUID}/policy/ftdnatpolicies/{self.nat_policy_id}/autonatrules/{entry['id']}"
                resp = self.putData(url, entry)
                if resp:
                    console.print(
                        f"[green][bold]Updated NAT entry ID {entry['id']} successfully."
                    )
                # FMC rate limit is 120 requests per minute
                sleep(0.55)
        if resp:
            console.print(f"[green][bold]NAT rules uploaded successfully!")

    def getData(self, get_url):
        """
        General function for HTTP GET requests with authentication headres
        """
        # console.print(f"Sending GET to: {get_url}")
        resp = self.s.get(get_url, headers=self.headers, verify=False)
        if resp.status_code == 200:
            return resp.text
        if resp.status_code == 404:
            return None
        else:
            console.print("[red]Request FAILED. " + str(resp.status_code))
            console.print("\nError from FMC:")
            console.print(resp.text)

    def putData(self, put_url, put_data):
        """
        General function for HTTP POST requests with authentication headers & some data payload
        """
        # console.print(f"Sending PUT to: {put_url}")
        resp = self.s.put(put_url, headers=self.headers, json=put_data, verify=False)
        # 200 for successful object update
        if resp.status_code == 200:
            return resp.text
        # 201 returned for most successful object creations
        if resp.status_code == 201:
            return resp.text
        # 202 is returned for accepted request
        if resp.status_code == 202:
            return resp.text
        else:
            console.print("[red]Request FAILED. " + str(resp.status_code))
            console.print("\nError from FMC:")
            console.print(resp.text)
            console.print("\nData Sent by Script:")
            console.print(put_data)

    def postData(self, post_url, post_data):
        """
        General function for HTTP POST requests with authentication headers & some data payload
        """
        # console.print(f"Sending PUT to: {post_url}")
        resp = self.s.post(post_url, headers=self.headers, json=post_data, verify=False)
        # 201 returned for most successful object creations
        if resp.status_code == 201:
            return resp.text
        # 202 is returned for accepted request
        if resp.status_code == 202:
            return resp.text
        else:
            console.print("[red]Request FAILED. " + str(resp.status_code))
            console.print("\nError from FMC:")
            console.print(resp.text)


def main():
    """
    Main flow of script execution
    """
    console.print("")
    console.print(Panel.fit("  -- Start --  "))
    console.print("")

    console.print("")
    console.print(Panel.fit("Connect to FMC", title="Step 1"))
    fmc = FirePower()

    console.print("")
    console.print(Panel.fit("Find NAT Policy UUID", title="Step 2"))
    fmc.getNATPolicyUUID()

    console.print("")
    console.print(Panel.fit("Find Interface Group UUIDs", title="Step 3"))
    fmc.getInterfaceGroups()

    console.print("")
    console.print(
        Panel.fit(f"Export Auto-NAT rules from {TARGET_NAT_POLICY}", title="Step 4")
    )
    fmc.getNATRules("auto")

    console.print("")
    console.print(
        Panel.fit(f"Export Manual-NAT rules from {TARGET_NAT_POLICY}", title="Step 5")
    )
    fmc.getNATRules("manual")

    console.print("")
    console.print(Panel.fit(f"Process Interface Updates", title="Step 6"))
    fmc.processNATRules()

    # Prompt to confirm & continue
    console.print("")
    if not Confirm.ask(f"Send updated NAT rules to FMC?"):
        sys.exit(1)

    console.print("")
    console.print(Panel.fit(f"Push Auto-NAT updates to FMC", title="Step 7"))
    fmc.updateNATRules("auto")

    console.print("")
    console.print(Panel.fit(f"Push Manual-NAT updates to FMC", title="Step 8"))
    fmc.updateNATRules("manual")

    console.print("")
    console.print(Panel.fit("  -- Finished --  "))
    console.print("")


if __name__ == "__main__":
    main()
