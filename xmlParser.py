#
# Copyright (C) 2019-2024, HENSOLDT Cyber GmbH
# 
# SPDX-License-Identifier: GPL-2.0-or-later
#
# For commercial licensing, contact: info.cyber@hensoldt.net
#

import sys
import xml.etree.ElementTree as ET
import subprocess

keysXmlPath = sys.argv[1]           # path to the xml file that contains the key information
toolExecutablePath = sys.argv[2]    # path to the keystore provisioning tool executable

tree = ET.parse(keysXmlPath)
root = tree.getroot()

for elem in root:
    params = []
    for node in elem:
        params.append(node.text)

    process = subprocess.Popen(
                [toolExecutablePath] + params,
                stdout=subprocess.PIPE,
                shell=False,
                universal_newlines=True)

    (output, err) = process.communicate()
    print(output)
