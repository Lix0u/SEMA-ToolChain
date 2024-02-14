from abc import abstractmethod, ABC
import json
import os
import numpy as np


class Manager(ABC):
    @abstractmethod
    def save(self):
        """
        Saves the data.
        """
        pass

    @abstractmethod
    def add(self, key, item, threshold, custom_sim_proc):
        pass

    @abstractmethod
    def get(self, key):
        pass


class JsonManager(Manager):
    def __init__(self, path):
        self.path = path
        if not os.path.exists(self.path):
            self.json_data = {}
        else:
            with open(self.path, "r") as f:
                self.json_data = json.load(f)

    def save(self):
        json.dump(self.json_data, open(self.path, "w"), indent=4)

    def add(self, key, embedding, threshold, custom_sim_proc):
        # item is a numpy array it cannot be serialized
        # so we convert it to a list
        if isinstance(embedding, np.ndarray):
            i = embedding.tolist()
        else:
            i = embedding
        self.json_data[key] = {"embedding": i, "threshold": threshold, "custom_sim_proc": custom_sim_proc}
        self.save()

    def get(self, key):
        # item is a list we convert it to a numpy array
        if key not in self.json_data:
            return None
        item = self.json_data[key]["embedding"]
        i = np.array(item)
        return i, self.json_data[key]["threshold"], self.json_data[key]["custom_sim_proc"]

    def get_all_names(self):
        return list(self.json_data.keys())
