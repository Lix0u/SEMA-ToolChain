import os
import random
from rich import print as rprint
import subprocess

# go to working directory
os.chdir(os.path.abspath(__file__).split('/test/')[0])

# choose some random sample out of the folder src/databases/malware/warzone and src/databases/malware/warzone3
n_samples_warzone = 2
n_samples_warzone3 = 4

warzone = os.listdir('src/databases/malware/warzone')
warzone3 = os.listdir('src/databases/malware/warzone3')

sample = [os.path.join('src/databases/malware/warzone', file) for file in random.sample(warzone, n_samples_warzone)] + [os.path.join('src/databases/malware/warzone3', file) for file in random.sample(warzone3, n_samples_warzone3)]


for s in sample:
    command_SAFE = f"python3 src/SemaSCDG/SemaSCDG.py --DFS --hooks_SAFE --sim_file --verbose_scdg {s}"
    output_SAFE = f"test/ToolChainSCDG/SAFE/output_test_SAFE_implementation/output_warzone_SAFE_{s.split('/')[-1][:6]}.txt"
    command_no_SAFE = f"python3 src/SemaSCDG/SemaSCDG.py --DFS --hooks --sim_file --verbose_scdg {s}"
    output_no_SAFE = f"test/ToolChainSCDG/SAFE/output_test_SAFE_implementation/output_warzone_no_SAFE_{s.split('/')[-1][:6]}.txt"
    rprint("\n\n\n"+command_SAFE+"\n\n\n")
    subprocess.run(command_SAFE.split(' '), stdout=open(output_SAFE, 'w'), stderr=subprocess.STDOUT)
    rprint("\n\n\n"+command_no_SAFE+"\n\n\n")
    subprocess.run(command_no_SAFE.split(' '), stdout=open(output_no_SAFE, 'w'), stderr=subprocess.STDOUT)
    