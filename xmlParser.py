import sys
import xml.etree.ElementTree as ET
from subprocess import Popen, PIPE

keysXmlPath = sys.argv[1]           # path to the xml file that contains the key information
toolExecutablePath = sys.argv[2]    # path to the keystore provisioning tool executable

tree = ET.parse(keysXmlPath)
root = tree.getroot()

for elem in root:
    params = []
    for node in elem:
        params.append(node.text)
    
    process = Popen([toolExecutablePath] + params, stdout=PIPE)
    (output, err) = process.communicate()
    print(output)
