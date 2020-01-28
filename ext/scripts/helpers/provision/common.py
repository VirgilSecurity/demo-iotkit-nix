import os
from pathlib import Path

# Paths
SCRIPT_FOLDER = str(Path(__file__).resolve().parent)
OUTPUT_FOLDER = os.path.join(SCRIPT_FOLDER, 'output')

TP_CONFIG_PATH = os.path.join(OUTPUT_FOLDER, 'trust-provisioner.conf')
TP_PROVISION_PACK_FOLDER = os.path.join(OUTPUT_FOLDER, 'provision-pack')
FACTORY_INFO_JSON_PATH = os.path.join(OUTPUT_FOLDER, 'factory-info.json')

INITIALIZER_OUTPUT = os.path.join(OUTPUT_FOLDER, 'initializer-output.txt')
INITIALIZER_INFO_OUTPUT = os.path.join(OUTPUT_FOLDER, 'initializer-info-output.txt')
