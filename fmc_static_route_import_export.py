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

import sys
import json
import requests
from requests.api import get, post, put
from requests.auth import HTTPBasicAuth
from requests.models import Response
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm


console = Console()

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

#######################
# Set FMC details & login credentials:
USERNAME = ""
PASSWORD = ""
FMC = ""

# Set Target devices to migrate static routes from:
SOURCE_DEVICE_NAME = ""
DESTINATION_DEVICE_NAME = ""
#######################

PLATFORM_URL = "https://" + FMC + "/api/fmc_platform/v1"
CONFIG_URL = "https://" + FMC + "/api/fmc_config/v1"


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

    def getDeviceUUID(self, device_name):
        """
        Retrieve device UUID by name
        """
        url = f"{CONFIG_URL}/domain/{self.global_UUID}/devices/devicerecords"
        resp = self.getData(url)
        if resp:
            resp_json = json.loads(resp)
            for obj in resp_json["items"]:
                if obj["name"] == device_name:
                    console.print(f"Found UUID for device {device_name}: {obj['id']}")
                    return obj["id"]
            # If UUID not found:
            console.print(f"[red]Could not find UUID for device: {device_name}")
            sys.exit(1)
        else:
            console.print(f"[red]Could not find UUID for device: {device_name}")
            sys.exit(1)

    def getStaticRoutes(self, device_uuid):
        """
        Function to retrieve static routing config from a target device UUID
        """
        self.source_static_routes = []
        console.print("Querying FMC...")
        url = f"{CONFIG_URL}/domain/{self.global_UUID}/devices/devicerecords/{device_uuid}/routing/ipv4staticroutes?expanded=true&limit=1000"
        resp = self.getData(url)
        if resp:
            resp_json = json.loads(resp)
            console.print(f"FMC returned {resp_json['paging']['count']} routes")
            console.print(f"\nProcessing output...")
            for obj in resp_json["items"]:
                static_route_entry = {}
                static_route_entry["interfaceName"] = obj["interfaceName"]
                static_route_entry["selectedNetworks"] = obj["selectedNetworks"]
                static_route_entry["metricValue"] = obj["metricValue"]
                static_route_entry["type"] = obj["type"]
                static_route_entry["isTunneled"] = obj["isTunneled"]

                # No gateway if Null0 route
                try:
                    static_route_entry["gateway"] = obj["gateway"]
                except KeyError:
                    pass
                # Skip key for route tracking if not configured
                try:
                    static_route_entry["routeTracking"] = obj["routeTracking"]
                except KeyError:
                    pass
                self.source_static_routes.append(static_route_entry)
        console.print(f"Saved {len(self.source_static_routes)} static route entries")

    def setStaticRoutes(self, device_uuid):
        """
        Upload list of static routes to a new device
        """
        url = f"{CONFIG_URL}/domain/{self.global_UUID}/devices/devicerecords/{device_uuid}/routing/ipv4staticroutes?bulk=true"
        resp = self.postData(url, self.source_static_routes)
        if resp:
            console.print(f"[green][bold]Routes uploaded successfully!")

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
    console.print(Panel.fit("Find Device UUIDs", title="Step 2"))
    sourceUUID = fmc.getDeviceUUID(SOURCE_DEVICE_NAME)
    destUUID = fmc.getDeviceUUID(DESTINATION_DEVICE_NAME)

    console.print("")
    console.print(
        Panel.fit(f"Export Static Routes from {SOURCE_DEVICE_NAME}", title="Step 3")
    )
    fmc.getStaticRoutes(sourceUUID)

    # Prompt to confirm & continue
    console.print("")
    if not Confirm.ask(f"Import routes to {DESTINATION_DEVICE_NAME}?"):
        sys.exit(1)

    console.print("")
    console.print(
        Panel.fit(f"Upload Static Routes to {DESTINATION_DEVICE_NAME}", title="Step 4")
    )
    console.print(
        "Note: If this call fails, [bold]no[/bold] routes will be uploaded & error will be displayed below.\n"
    )
    fmc.setStaticRoutes(destUUID)

    console.print("")
    console.print(Panel.fit("  -- Finished --  "))
    console.print("")


if __name__ == "__main__":
    main()
