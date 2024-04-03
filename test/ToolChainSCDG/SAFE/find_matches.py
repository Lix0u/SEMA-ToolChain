from pathlib import Path
import sys
import os
# print(Path(__file__).parents[3])
sys.path.append(str(Path(__file__).parents[3]))
sys.path.append(str(Path(__file__).parents[3])+'/src/SemaSCDG/plugin')
from PluginHooksSAFE2 import SAFE

safe = SAFE("src/SemaSCDG/plugin/SAFE/safe.pb")

folder = "src/databases/malware/warzone2" # Path to the folder containing the warzone vscodé samples
output_file = "test/ToolChainSCDG/SAFE/output_find_matches/warzone2.json"

files = os.listdir(folder)
files.sort()
files = [os.path.join(folder, file) for file in files]
matches = {}
for file in files:
    similar_functions = safe.get_functions_similar_to_db(file)
    print(similar_functions)