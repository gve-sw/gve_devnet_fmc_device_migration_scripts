# FMC Device Migration Scripts

This repo contains scripts to assist in device migrations within FMC.

`fmc_static_route_import_export.py` - Allows exporting a FTD device's static routes & importing them to a new device.

`fmc_update_nat_interfaces.py` - Takes in a mapping of old/new interface groups & updates each rule.

## Contacts
* Matt Schmitz (mattsc@cisco.com)

## Solution Components
* Firepower Management Center
* Firepower Threat Defence

## Installation/Configuration

**Clone repo:**
```bash
git clone <repo_url>
```

**Install required dependancies:**
```bash
pip install -r requirements.txt
```

**Configure Scripts**

In each script, there will be a small configuration section for FMC details (IP, Username, and password):

```
# Set FMC details & login credentials:
USERNAME = ""
PASSWORD = ""
FMC = ""
```

For `fmc_static_route_import_export.py`, please configure the names of the source & destination FTD devices:

```
# Set Target devices to migrate static routes from:
SOURCE_DEVICE_NAME = ""
DESTINATION_DEVICE_NAME= ""
```


For `fmc_update_nat_interfaces.py`, please configure the target NAT policy to edit & the location/name of the interface group mapping file:
```
# Set Target NAT policy to edit:
TARGET_NAT_POLICY = ""

# Mapping file:
NAT_INTERFACE_MAP = ""
```

The mapping file is YAML, and takes the format of `OLD_INTGRP_NAME: NEW_INTGRP_NAME`

For example:
```
OLD_INT-01: NEW_INT-01
OLD_INT-02: NEW_INT-02
OLD_INT-03: NEW_INT-03
```

## Usage

Run the application with the following command & follow the prompts:

```
python <scriptname>.py
```

# Screenshots

**Example Static Route Migration Script:**

![/IMAGES/static-route.png](/IMAGES/static-route.png)

**Example from NAT policy update script:**

![/IMAGES/nat-updates.png](/IMAGES/nat-updates.png)


### LICENSE

Provided under Cisco Sample Code License, for details see [LICENSE](LICENSE.md)

### CODE_OF_CONDUCT

Our code of conduct is available [here](CODE_OF_CONDUCT.md)

### CONTRIBUTING

See our contributing guidelines [here](CONTRIBUTING.md)

#### DISCLAIMER:
<b>Please note:</b> This script is meant for demo purposes only. All tools/ scripts in this repo are released for use "AS IS" without any warranties of any kind, including, but not limited to their installation, use, or performance. Any use of these scripts and tools is at your own risk. There is no guarantee that they have been through thorough testing in a comparable environment and we are not responsible for any damage or data loss incurred with their use.
You are responsible for reviewing and testing any scripts you run thoroughly before use in any non-testing environment.