try:
    from .SAFE.FunctionAnalyzerRadare import RadareFunctionAnalyzer
    from .SAFE.FunctionNormalizer import FunctionNormalizer
    from .SAFE.InstructionsConverter import InstructionsConverter
    from .SAFE.SAFEEmbedder import SAFEEmbedder
    from .SAFE.db_manager import JsonManager
except:
    from src.SemaSCDG.plugin.SAFE.FunctionAnalyzerRadare import RadareFunctionAnalyzer
    from src.SemaSCDG.plugin.SAFE.FunctionNormalizer import FunctionNormalizer
    from src.SemaSCDG.plugin.SAFE.InstructionsConverter import InstructionsConverter
    from src.SemaSCDG.plugin.SAFE.SAFEEmbedder import SAFEEmbedder
    from src.SemaSCDG.plugin.SAFE.db_manager import JsonManager
from argparse import ArgumentParser
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity
from time import sleep


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

    """
        returns the embedding vector of a function
    """

    def embedd_function(self, filename, address):
        analyzer = RadareFunctionAnalyzer(filename, use_symbol=False, depth=0)
        functions = analyzer.analyze()
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
                    if sim > self.db_functions.get(function_db)["threshold"]:
                        print("\n\n\n\n\n\n\n\n\n\n\n")
                        print(
                            "Function " + function_db + " is similar to " + function_exe
                        )
                        print("\n\n\n\n\n\n\n\n\n\n\n")
                        sleep(3)
                        if (
                            self.db_functions.get(function_db)["customSimProc"]
                            is not None
                        ):
                            project.hook(
                                db_exe[function_exe]["address"],
                                call_sim.custom_simproc_windows["custom_hook"][
                                    self.db_functions.get(function_db)["customSimProc"]
                                ](plength=db_exe[function_exe]["len"]),
                                length=db_exe[function_exe]["len"],
                            )

    """
        add the embeddings of all the functions of the executable to the database
    """

    def embedd_executable(self, filename):
        if filename.split("/")[-1] in self.db_executable.get_all_names():
            pass
        else:
            analyzer = RadareFunctionAnalyzer(filename, use_symbol=False, depth=0)
            functions = analyzer.analyze()
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
                }
            self.db_executable.add(filename.split("/")[-1], embeddings)

    def get_processed_binaries(self):
        return self.db_executable.get_all_names()


if __name__ == "__main__":
    # add the target fuction to the database
    # run from src folder
    safe = SAFE("src/SemaSCDG/plugin/SAFE/safe.pb")

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
        help="Threshold of the function to embedd",
    )
    parser.add_argument(
        "-c",
        "--customSimProc",
        dest="customSimProc",
        required=True,
        help="Custom procedure associated with the function to embedd",
    )
    parser.add_argument(
        "-n",
        "--name",
        dest="name",
        required=True,
        help="Name of the function to add to the database or to compare",
    )
    args = parser.parse_args()

    embbedding = safe.embedd_function(args.file, int(args.address, 16))

    safe.db_functions.add(
        args.name,
        {
            "embedding": embbedding.tolist(),
            "customSimProc": args.customSimProc,
            "threshold": args.threshold,
        },
    )
