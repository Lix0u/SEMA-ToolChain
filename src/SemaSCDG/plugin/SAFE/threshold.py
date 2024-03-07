import os
import numpy as np
import json
from sklearn.metrics.pairwise import cosine_similarity
import psutil

def kill_radare_process():
    """kill all radare2 processes
    """
    for proc in psutil.process_iter():
        if proc.name() == "radare2":
            proc.kill()
            
def find_threshold(safe, folders, binary, address, output=None, debug=False):
    """find the smallest threshold that only matches the same function

    Args:
        folders (list): list of the folders containing binaries of the same family
        binary (string): path to the binary from which the signature is extracted
        address (int): address of the function from which the signature is extracted
        output (string): path to the output file where the results will be stored. If None, the results will not be stored
        debug (boolean): if True, the full address of the matching functions will be stored in the output file and the results will be printed

    Returns:
        int: the smallest threshold that only matches the same function
    """
    binary_name = binary.split('/')[-1]
    if debug:
        thresholds = {1: [], 0.98: [], 0.95: [], 0.93: [], 0.90: []}
    else:
        thresholds = {1: 0, 0.98: 0, 0.95: 0, 0.93: 0, 0.90: 0}

    embedding = safe.embedd_function(binary, address)
    if embedding is None:
        print("Function not found")
        exit(1)
    files = []
    for folder in folders:
        files += list(map(lambda x: os.path.join(folder, x), os.listdir(folder)))
    files.sort()
    for file in files:
        file_name = file.split('/')[-1]
        if file_name == binary_name:
            continue
        print("Processing file: " + file_name)
        best_sim = 0
        best_emb = None
        embeddings = safe.get_embeddings(file)
        kill_radare_process()
        for emb in embeddings.keys():
            sim = cosine_similarity(np.array(embedding), np.array(embeddings[emb]['embedding']))
            if sim > best_sim:
                best_sim = sim
                best_emb = emb
        for threshold in thresholds.keys():
            if round(best_sim[0][0],3) >= threshold:
                if debug:
                    thresholds[threshold].append(file_name + ':' + hex(embeddings[best_emb]['address']))
                else:
                    thresholds[threshold] += 1
                break
        if output != None:
            json.dump(thresholds, open(output, 'w'), indent=4)
    if debug:
        for threshold in thresholds.keys():
            print("Threshold " + str(threshold) + " has " + str(len(thresholds[threshold])) + " matches")
    max_thresh_found = False
    thresh = list(thresholds.keys())
    thresh.sort(reverse=True) # so that we can see where we are in the folder
    for threshold in thresh:
        if debug:
            count = len(thresholds[threshold])
        else:
            count = thresholds[threshold]
        if count > 0:
            if not max_thresh_found:
                final_threshold = threshold
                max_thresh_found = True
            else:
                break
        else:
            final_threshold = threshold
    if debug:
        print("Final threshold: " + str(final_threshold))
    return final_threshold