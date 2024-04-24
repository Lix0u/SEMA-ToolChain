# install gdown id not installed
import sys
import os
from time import sleep
from rich import print as rprint
try:    
    import gdown
except ImportError:
    os.system('python3 -m pip install gdown') # do it like this to avoid error: externally-managed-environment
    sleep(10)
    import gdown

id_model = '1Kwl8Jy-g9DXe1AUjUZDhJpjRlDkB4NBs'
id_i2v = '1CqJVGYbLDEuJmJV6KH4Dzzhy-G12GjGP'
base_path = os.path.abspath(__file__).split('/SEMA')[0] + '/SEMA-ToolChain/src/SemaSCDG/plugin/SAFE/'
model_name='safe.pb'
i2v_compress_name='i2v.tar.bz2'

rprint("Downloading i2v model... ")
rprint(i2v_compress_name)
gdown.download(id=id_i2v, output=i2v_compress_name)
rprint("Downloading SAFE model... ")
gdown.download(id=id_model, output=model_name)

# Decompressing i2v model and placing in the folder
rprint("Decompressing i2v model and placing in " + str(base_path+'i2v/') )
os.system('tar -xvf '+i2v_compress_name+' -C '+base_path)

#delete compressed file
rprint("delete compressed file")
os.system('rm '+i2v_compress_name)

#move SAFE model to the folder
rprint("move SAFE model to the folder")
os.system('mv '+model_name+' '+base_path)
