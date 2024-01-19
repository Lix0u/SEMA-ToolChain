import tensorflow.compat.v1 as tf # we need tensorflow 1 
# SAFE TEAM
# distributed under license: GPL 3 License http://www.gnu.org/licenses/

class SAFEEmbedder:

    def __init__(self, model_file):
        tf.disable_v2_behavior() # disable behavior form tensorflow 2
        self.model_file = model_file # Safe trained model to generate function embeddings
        self.session = None 
        self.x_1 = None
        self.adj_1 = None
        self.len_1 = None
        self.emb = None

    def loadmodel(self):
        with tf.gfile.GFile(self.model_file, "rb") as f: # GFile = file I/O wrapper without thread locking, rb = read binary
            graph_def = tf.GraphDef() 
            graph_def.ParseFromString(f.read())

        with tf.Graph().as_default() as graph:
            tf.import_graph_def(graph_def)

        sess = tf.Session(graph=graph)
        self.session = sess

        return sess

    def get_tensor(self):
        self.x_1 = self.session.graph.get_tensor_by_name("import/x_1:0")
        self.len_1 = self.session.graph.get_tensor_by_name("import/lengths_1:0")
        self.emb = tf.nn.l2_normalize(self.session.graph.get_tensor_by_name('import/Embedding1/dense/BiasAdd:0'), axis=1)

    def embedd(self, nodi_input, lengths_input):

        out_embedding= self.session.run(self.emb, feed_dict = {
                                                    self.x_1: nodi_input,
                                                    self.len_1: lengths_input})

        return out_embedding
