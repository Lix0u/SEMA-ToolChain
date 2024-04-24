from re import T
import sys
from pathlib import Path

from sklearn.preprocessing import binarize
sys.path.append(str(Path(__file__).parents[3])+'/src/SemaSCDG/plugin')
sys.path.append(str(Path(__file__).parents[3])+'/src/SemaSCDG/plugin/SAFE')
print(sys.path)
from threshold import find_threshold
from PluginHooksSAFE import SAFE

safe = SAFE("src/SemaSCDG/plugin/SAFE/safe.pb")
folders = ["src/databases/malware/warzone", "src/databases/malware/warzone3"]
binary = "src/databases/malware/warzone/d565677b0818122a241235109dc8ed5b69983f0fb231dabe683516ff3078cbff.exe"
address = "0x411bf8"
output = "test/ToolChainSCDG/SAFE/output_test_threshold/test_auto_threshold_output.txt"
debug = True

find_threshold(safe, folders, binary, address, output, debug)