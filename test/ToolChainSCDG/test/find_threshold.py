import sys
import os
import numpy as np
from argparse import ArgumentParser
print(os.path.exists('src/SemaSCDG/plugin/PluginHooksSAFE2.py'))



from ..PluginHooksSAFE2 import SAFE
import json
from sklearn.metrics.pairwise import cosine_similarity

if __name__ == '__main__':
    arg_parser = ArgumentParser()
    arg_parser.add_argument("-f","--folder", help="Folder containing the executables", required=True)
    args = arg_parser.parse_args()
    safe = SAFE("src/SemaSCDG/plugin/SAFE/safe.pb")
    if os.path.exists('test/ToolChainSCDG/SAFE/data.jon'):
        with open('test/ToolChainSCDG/SAFE/data.json', 'r') as f:
            data = json.load(f)
    else:
        data = {}
    first_file = True
    c = 0
    folders = args.folder.split(',')
    for folder in folders:
        for file in os.listdir(args.folder):
            print ("Processing file: " + file)
            if first_file:
                first_file = False
                embeddings = safe.get_embeddings(args.folder + "/" + file)
                thresh = {1:[], 0.98:[], 0.95:[], 0.93:[], 0.90:[]}
                for embedding in embeddings.keys():
                    embeddings[embedding].update(thresh)
                    embeddings[embedding]['embedding'] = embeddings[embedding]['embedding']
                    data[embedding] = embeddings[embedding]
            else:
                if c > 5:
                    break
                c += 1
                embeddings = safe.get_embeddings(args.folder + "/" + file)
                for embedding in embeddings.keys():
                    for d in data.keys():
                        sim = cosine_similarity(np.array(embeddings[embedding]['embedding']), np.array(data[d]['embedding']))
                        for threshold in thresh.keys():
                            if sim >= threshold:
                                data[embedding][threshold].append(file+':'+hex(embeddings[embedding]['address']))
                json.dump(data, open('test/ToolChainSCDG/SAFE/data.json', 'w'), indent=4)

    #remove all the functions that are too small and have too many matches
    n_files = len(os.listdir(args.folder))
    keys = list(data.keys())
    for d in keys:
        if len(data[d][1]) > n_files:
            del data[d]