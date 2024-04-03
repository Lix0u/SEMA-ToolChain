try:
    from .SAFE.FunctionAnalyzerRadare import RadareFunctionAnalyzer
    from .SAFE.FunctionNormalizer import FunctionNormalizer
    from .SAFE.InstructionsConverter import InstructionsConverter
    from .SAFE.SAFEEmbedder import SAFEEmbedder
    from .SAFE.db_manager import JsonManager
    from .SAFE.threshold import find_threshold
except:
    import os
    import sys
    sys.path.append(os.getcwd())
    #import the classes from the src folder
    from SAFE.FunctionAnalyzerRadare import RadareFunctionAnalyzer
    from SAFE.FunctionNormalizer import FunctionNormalizer
    from SAFE.InstructionsConverter import InstructionsConverter
    from SAFE.SAFEEmbedder import SAFEEmbedder
    from SAFE.db_manager import JsonManager
    from SAFE.threshold import find_threshold
from argparse import ArgumentParser, BooleanOptionalAction
from matplotlib.pylab import f
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity
from time import sleep
import os
import psutil


class SAFE:
    def __init__(self, model):
        self.converter = InstructionsConverter(
            "src/SemaSCDG/plugin/SAFE/i2v/word2id.json"
        )
        self.normalizer = FunctionNormalizer(max_instruction=150)
        self.embedder = SAFEEmbedder(model)
        self.embedder.loadmodel()
        self.embedder.get_tensor()
        self.db_executable = JsonManager("src/SemaSCDG/plugin/SAFE/db_exe.json")
        self.db_functions = JsonManager("src/SemaSCDG/plugin/SAFE/db_func.json")
        
    def kill_radare_process(self):
        for proc in psutil.process_iter():
            if proc.name() == "radare2" and proc.ppid() == os.getpid():
                proc.kill()

    """
        returns the embedding vector of a function
    """
    def embed_function(self, filename, address):
        if isinstance(address, str):
            address = int(address, 16)
        analyzer = RadareFunctionAnalyzer(filename, use_symbol=False, depth=0)
        functions = analyzer.analyze()
        self.kill_radare_process()
        instructions_list = None
        for function in functions:
            if functions[function]["address"] == address:
                instructions_list = functions[function]["filtered_instructions"]
                break
        if instructions_list is None:
            print("Function not found")
            return None
        converted_instructions = self.converter.convert_to_ids(instructions_list)
        instructions, length = self.normalizer.normalize_functions(
            [converted_instructions]
        )
        embedding = self.embedder.embedd(instructions, length)
        return embedding

    def compare_exe(self, filename, project, call_sim):
        if filename.split("/")[-1] in self.db_executable.get_all_names():
            db_exe = self.db_executable.get(filename.split("/")[-1])
            for function_exe in db_exe:
                for function_db in self.db_functions.get_all_names():
                    sim = cosine_similarity(
                        np.array(db_exe[function_exe]["embedding"]),
                        np.array(self.db_functions.get(function_db)["embedding"]),
                    )
                    if round(sim[0][0],3) >= float(self.db_functions.get(function_db)["threshold"]):
                        print("\n\n\n\n\n\n\n\n\n\n\n")
                        print(
                            "Function " + function_db + " is similar to " + function_exe + " with a similarity of " + str(sim)
                        )
                        print("\n\n\n\n\n\n\n\n\n\n\n")
                        sleep(3)
                        if (
                            self.db_functions.get(function_db)["customSimProc"]
                            is not None
                        ):
                            # if last byte is 0xc3 (ret) then we need to remove it
                            # with open(filename, "rb") as f:
                            #     #read byte at the end of the function
                            #     f.seek(db_exe[function_exe]["address"] + db_exe[function_exe]["len"]-1)
                            #     last_byte = f.read(1)
                            if db_exe[function_exe]["last_instr"] == "X_ret":
                                print(db_exe[function_exe]["len"]-1)
                                project.hook(
                                    db_exe[function_exe]["address"],
                                    call_sim.custom_simproc_windows["custom_hook"][
                                        self.db_functions.get(function_db)["customSimProc"]
                                    ](plength=db_exe[function_exe]["len"]-1),
                                    length=db_exe[function_exe]["len"]-1,
                                )
                            else:
                                print(db_exe[function_exe]["len"])
                                project.hook(
                                    db_exe[function_exe]["address"],
                                    call_sim.custom_simproc_windows["custom_hook"][
                                        self.db_functions.get(function_db)["customSimProc"]
                                    ](plength=db_exe[function_exe]["len"]),
                                    length=db_exe[function_exe]["len"],
                                )
                        break
        else:
            print("Executable not found in the database")
            # TODO: add the executable to the database

    """
        add the embeddings of all the functions of the executable to the database
    """

    def embedd_executable(self, filename):
        if filename.split("/")[-1] in self.db_executable.get_all_names():
            pass
        else:
            analyzer = RadareFunctionAnalyzer(filename, use_symbol=False, depth=0)
            functions = analyzer.analyze()
            self.kill_radare_process()
            embeddings = {}
            for function in functions:
                instructions_list = functions[function]["filtered_instructions"]
                converted_instructions = self.converter.convert_to_ids(
                    instructions_list
                )
                instructions, length = self.normalizer.normalize_functions(
                    [converted_instructions]
                )
                embedding = self.embedder.embedd(instructions, length)
                # use the function address in hexadecimal to easily find the function if needed
                embeddings[hex(functions[function]["address"])] = {
                    "embedding": embedding.tolist(),
                    "address": functions[function]["address"],
                    "len": functions[function]["length"],
                    "last_instr": functions[function]["last_instr"],
                }
            self.db_executable.add(filename.split("/")[-1], embeddings)

    def get_embeddings(self, filename):
        analyzer = RadareFunctionAnalyzer(filename, use_symbol=False, depth=0)
        functions = analyzer.analyze()
        self.kill_radare_process()
        embeddings = {}
        for function in functions:
            instructions_list = functions[function]["filtered_instructions"]
            converted_instructions = self.converter.convert_to_ids(
                instructions_list
            )
            instructions, length = self.normalizer.normalize_functions(
                [converted_instructions]
            )
            embedding = self.embedder.embedd(instructions, length)
            # use the function address in hexadecimal to easily find the function if needed
            embeddings[hex(functions[function]["address"])] = {
                "embedding": embedding.tolist(),
                "address": functions[function]["address"],
            }
        return embeddings

    def get_processed_binaries(self):
        return self.db_executable.get_all_names()
    
    def get_functions_similar_to_db(self,filename):
        if filename.split("/")[-1] in self.db_executable.get_all_names():
            exe = self.db_executable.get(filename.split("/")[-1])
        else:
            analyzer = RadareFunctionAnalyzer(filename, use_symbol=False, depth=0)
            functions = analyzer.analyze()
            self.kill_radare_process()
            exe = {}
            for function in functions:
                instructions_list = functions[function]["filtered_instructions"]
                converted_instructions = self.converter.convert_to_ids(
                    instructions_list
                )
                instructions, length = self.normalizer.normalize_functions(
                    [converted_instructions]
                )
                embedding = self.embedder.embedd(instructions, length)
                # use the function address in hexadecimal to easily find the function if needed
                exe[hex(functions[function]["address"])] = {
                    "embedding": embedding.tolist(),
                    "address": functions[function]["address"],
                    "len": functions[function]["length"],
                    "last_instr": functions[function]["last_instr"],
                }
        similar_functions = {}
        for function_exe in exe:
            for function_db in self.db_functions.get_all_names():
                sim = cosine_similarity(
                    np.array(exe[function_exe]["embedding"]),
                    np.array(self.db_functions.get(function_db)["embedding"]),
                )
                if round(sim[0][0],3) >= float(self.db_functions.get(function_db)["threshold"]):
                    similar_functions[function_exe] = similar_functions.get(function_exe, []).append(hex(exe[function_exe]["address"]))
        return similar_functions
            


if __name__ == "__main__":
    # add the target fuction to the database
    # run from src folder

    parser = ArgumentParser(description="Add a function to the database")
    parser.add_argument(
        "-f",
        "--file",
        dest="file",
        required=True,
        help="File that contains the function to embedd",
    )
    parser.add_argument(
        "-a",
        "--address",
        dest="address",
        required=True,
        help="Address of the function to embedd",
    )
    parser.add_argument(
        "-t",
        "--threshold",
        dest="threshold",
        required=False,
        default=0.95,
        help="Manually set the threshold for the function to be considered similar to another one",
    )
    parser.add_argument(
        "-T",
        "--autoThreshold",
        dest="autoThreshold",
        action= BooleanOptionalAction,
        default=False,
        help="Automatically set the threshold for the function to be considered similar to another one (requires -F)",
    )    
    parser.add_argument(
        "-n",
        "--name",
        dest="name",
        required=True,
        help="Name of the function to add to the database or to compare",
    )
    parser.add_argument(
        "-c",
        "--customSimProc",
        dest="customSimProc",
        required=True,
        help="Custom similarity procedure to use if the function is similar to another one",
    )
    args, unknown = parser.parse_known_args()
    if args.autoThreshold: #TODO: fix help message
        parser.add_argument(
            "-F",
            "--folders",
            dest="folders",
            nargs="+",
            required=True,
            help="Folders containing the binaries of the same family",
        )
        parser.add_argument(
            "-o",
            "--outputFile",
            dest="outputFile",
            required=False,
            default="thresholds.json",
            help="Output file to save the threshold computation",
        )
        parser.add_argument(
            "-d",
            "--debug",
            dest="debug",
            action= BooleanOptionalAction,
            default=False,
            help="Print debug information",
        )
    
    args = parser.parse_args()

    safe = SAFE("src/SemaSCDG/plugin/SAFE/safe.pb")
    
    embbedding = safe.embed_function(args.file, int(args.address, 16))
    if args.autoThreshold:
        args.threshold = find_threshold(safe, args.folders, args.file, int(args.address,16), args.outputFile, args.debug)
    safe.db_functions.add(
        args.name,
        {
            "embedding": embbedding.tolist(),
            "customSimProc": args.customSimProc,
            "threshold": args.threshold,
        },
    )
