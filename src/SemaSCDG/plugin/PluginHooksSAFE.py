from sklearn.metrics.pairwise import cosine_similarity
from SAFE_configuration_files.asm_embedding.FunctionAnalyzerRadare import RadareFunctionAnalyzer
from argparse import ArgumentParser, BooleanOptionalAction
from SAFE_configuration_files.asm_embedding.FunctionNormalizer import FunctionNormalizer
from SAFE_configuration_files.asm_embedding.InstructionsConverter import InstructionsConverter
from SAFE_configuration_files.neural_network.SAFEEmbedder import SAFEEmbedder
from SAFE_configuration_files.db_manager import JsonManager
import sys

class PluginHooksSAFE:
    def __init__(self):
        self.db_manager = JsonManager("SemaSCDG/plugin/SAFE_configuration_files/db.json")
        self.model = "SemaSCDG/plugin/SAFE_configuration_files/SAFE_model/safe.pb"
        self.converter = InstructionsConverter("SemaSCDG/plugin/SAFE_configuration_files/SAFE_model/i2v/word2id.json")
        self.normalizer = FunctionNormalizer(max_instruction=150)
        self.embedder = SAFEEmbedder(self.model)
        self.embedder.loadmodel()
        self.embedder.get_tensor()

    def embed_function(self, filename, address):
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

    def add_embedding_to_db(self, embbeding, name, threshold=0.95, custom_sim_proc=None):
        self.db_manager.add(name, embbeding, threshold, custom_sim_proc)

    def add_custom_hooks(self, executable, project, call_sim):
        """
        Add custom hooks
        :param executable: executable to analyze
        :return: None
        """
        analyzer = RadareFunctionAnalyzer(executable, use_symbol=False, depth=0)
        functions = analyzer.analyze()
        registered_functions = self.db_manager.get_all()
        for registered_function in registered_functions:
            func = self.db_manager.get(registered_function)
            embedding = func["embedding"]
            threshold = func["threshold"]
            custom_sim_proc = func["custom_sim_proc"]
            for function in functions:
                instructions_list = functions[function]["filtered_instructions"]
                converted_instructions = self.converter.convert_to_ids(instructions_list)
                instructions, length = self.normalizer.normalize_functions(
                    [converted_instructions]
                )
                new_embedding = self.embedder.embedd(instructions, length)
                sim = cosine_similarity(embedding, new_embedding)
                if sim > threshold:
                    print("Found hook: " + registered_function + " at address: " + hex(functions[function]["address"]))
                    if custom_sim_proc is not None:
                        project.hook(
                            functions[function]["address"],
                            call_sim.custom_simproc_windows["custom_hook"][registered_function](plength= 0), # todo: add plength = function length
                            length=0 # todo: add length = function length
                        )
                    else:
                        print("No custom procedure found for function: " + registered_function)
                        sys.exit(1)



if __name__ == "__main__":
    # to add a function to the database
    parser = ArgumentParser(description="Safe Embedder")

    parser.add_argument(
        "-n",
        "--name",
        dest="name",
        required=True,
        help="Name of the function to add to the database or to compare",
    )

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
        help="Threshold for the similarity",
    )

    parser.add_argument(
        "-c",
        "--custom",
        dest="custom-sim-proc",
        required=False,
        help="Custom similarity procedure",
    )

    args = parser.parse_args()
    safe = PluginHooksSAFE()

    embedding = safe.embed_function(args.file, args.address)
    if embedding is None:
        print("Function not found")
        sys.exit(1)

    if args.threshold is not None:
        threshold = args.threshold
    else:
        threshold = 0.95

    if args.custom_sim_proc is not None:
        custom_sim_proc = args.custom_sim_proc
    else:
        custom_sim_proc = None

    safe.add_embedding_to_db(embedding, args.name, threshold, custom_sim_proc)

    # todo: function to add all the functions to the db
    # todo: add the possibility to change the db path