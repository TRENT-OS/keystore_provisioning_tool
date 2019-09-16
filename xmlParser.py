import sys
import xml.etree.ElementTree as ET
from subprocess import Popen, PIPE

keysXmlPath = sys.argv[1]           # path to the xml file that contains the key information
toolExecutablePath = sys.argv[2]    # path to the keystore provisioning tool executable

tree = ET.parse(keysXmlPath)
root = tree.getroot()

for elem in root:
    process = Popen([toolExecutablePath, elem[0].text, elem[1].text, elem[2].text, elem[3].text, elem[4].text], stdout=PIPE)
    (output, err) = process.communicate()
    print(output)
