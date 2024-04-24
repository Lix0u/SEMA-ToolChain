# this file is used to generate the database of known functions
import os
from rich import print as rprint
import json
import subprocess
from argparse import ArgumentParser, BooleanOptionalAction

# go to working directory
os.chdir(os.path.abspath(__file__).split('/src/')[0])

# open known_functions.json
with open('src/SemaSCDG/plugin/SAFE/known_functions.json', 'r') as file:
    known_functions = json.load(file)

# create the commands to run
command_auto_thresh = "python3 src/SemaSCDG/plugin/PluginHooksSAFE.py -f {file} -a {address} -n {name} -T -F {folders} -c {cutomHook} -o output.json"
command = "python3 src/SemaSCDG/plugin/PluginHooksSAFE.py -f {file} -a {address} -n {name} -t {threshold} -c {cutomHook} -o output.json"

for function in known_functions:
    f = known_functions[function]
    if f["threshold"] == 0:
        c = command_auto_thresh.format(file=f['file'], address=f['address'], name=f['name'], folders=" ".join(f['folders']), cutomHook=f['customHook'])
    else:
        c = command.format(file=f['file'], address=f['address'], name=f['name'], threshold=f["threshold"], cutomHook=f['customHook'])
    rprint("\n\n\n"+c+"\n\n\n")
    subprocess.run(c.split(' '))
    rprint(f"Function: {f['name']} has been added to the database")
    