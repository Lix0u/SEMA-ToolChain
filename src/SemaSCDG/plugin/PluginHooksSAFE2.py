from FunctionAnalyzerRadare import RadareFunctionAnalyzer
from FunctionNormalizer import FunctionNormalizer
from InstructionsConverter import InstructionsConverter
from SAFEEmbedder import SAFEEmbedder
from db_manager import JsonManager
from argparse import ArgumentParser
import os

class SAFE:
    def __init__(self, model):
        self.converter = InstructionsConverter("SemaSCDG/plugin/SAFE/i2v/word2id.json")
        self.normalizer = FunctionNormalizer(max_instruction=150)
        self.embedder = SAFEEmbedder(model)
        self.embedder.loadmodel()
        self.embedder.get_tensor()
        self.db_executable = JsonManager("SemaSCDG/plugin/SAFE/db_exe.json")
        self.db_functions = JsonManager("SemaSCDG/plugin/SAFE/db_func.json")

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

    """
        add the embeddings of all the functions of the executable to the database
    """

    def embedd_executable(self, filename, threshold=0.95):
        if filename.split("/")[-1] in self.db_executable.get_all_names():
            pass
        else:
            analyzer = RadareFunctionAnalyzer(filename, use_symbol=False, depth=0)
            functions = analyzer.analyze()
            embeddings = {}
            for function in functions:
                instructions_list = functions[function]["filtered_instructions"]
                converted_instructions = self.converter.convert_to_ids(instructions_list)
                instructions, length = self.normalizer.normalize_functions(
                    [converted_instructions]
                )
                embedding = self.embedder.embedd(instructions, length)
                # use the function address in hexadecimal to easily find the function if needed
                embeddings[hex(functions[function]["address"])] = {"embedding": embedding,
                                                                   "address": functions[function]["address"],
                                                                   "threshold": threshold}
            self.db_executable.add(filename.split("/")[-1], embeddings)

if __name__ == "__main__":
    #add the target fuction to the database
    #run from src folder
    safe = SAFE("SemaSCDG/plugin/SAFE/safe.pb")

    parser = ArgumentParser(description='Add a function to the database')
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
        help = "Custom procedure associated with the function to embedd",
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

    safe.db_functions.add(args.name, {"embedding": embbedding.tolist(), "customSimProc": args.customSimProc, "threshold": args.threshold})
