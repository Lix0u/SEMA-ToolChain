import os
import random
from rich import print as rprint
import subprocess

# go to working directory
os.chdir(os.path.abspath(__file__).split('/test/')[0])

# choose some random sample out of the folder src/databases/malware/warzone and src/databases/malware/warzone3
n_samples_warzone = len(os.listdir('src/databases/malware/warzone'))
n_samples_warzone3 = len(os.listdir('src/databases/malware/warzone3'))

warzone = os.listdir('src/databases/malware/warzone')
warzone3 = os.listdir('src/databases/malware/warzone3')

sample = [os.path.join('src/databases/malware/warzone', file) for file in random.sample(warzone, n_samples_warzone)] + [os.path.join('src/databases/malware/warzone3', file) for file in random.sample(warzone3, n_samples_warzone3)]
# sample = [os.path.join('src/databases/malware/warzone', file) for file in random.sample(warzone, n_samples_warzone)]

samples_done = os.listdir('test/ToolChainSCDG/SAFE/output_test_SAFE_implementation')

for s in sample:
    if f"output_warzone_SAFE_{s.split('/')[-1][:6]}.txt" not in samples_done:
        command_SAFE = f"python3 src/SemaSCDG/SemaSCDG.py --CDFS --count_block --hooks_SAFE --sim_file --verbose_scdg {s}"
        output_SAFE = f"test/ToolChainSCDG/SAFE/output_test_SAFE_implementation/output_warzone_SAFE_{s.split('/')[-1][:6]}.txt"
        rprint("\n\n\n"+command_SAFE+"\n\n\n")
        subprocess.run(command_SAFE.split(' '), stdout=open(output_SAFE, 'w'), stderr=subprocess.STDOUT)
    if f"output_warzone_no_SAFE_{s.split('/')[-1][:6]}.txt" not in samples_done:
        command_no_SAFE = f"python3 src/SemaSCDG/SemaSCDG.py --CDFS --count_block --hooks --sim_file --verbose_scdg {s}"
        output_no_SAFE = f"test/ToolChainSCDG/SAFE/output_test_SAFE_implementation/output_warzone_no_SAFE_{s.split('/')[-1][:6]}.txt"
        rprint("\n\n\n"+command_no_SAFE+"\n\n\n")
        subprocess.run(command_no_SAFE.split(' '), stdout=open(output_no_SAFE, 'w'), stderr=subprocess.STDOUT)
    