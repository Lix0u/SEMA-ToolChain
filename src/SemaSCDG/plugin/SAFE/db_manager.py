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
    def add(self, key, item):
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

    def add(self, key, item):
        # item is a numpy array it cannot be serialized
        # so we convert it to a list
        if isinstance(item, np.ndarray):
            i = item.tolist()
        else:
            i = item
        self.json_data[key] = i
        self.save()

    def get(self, key):
        # item is a list we convert it to a numpy array
        if key not in self.json_data:
            return None
        if isinstance(self.json_data[key], list):
            item = self.json_data[key]
            i = np.array(item)
            return i
        return self.json_data[key]

    def get_all_names(self):
        return list(self.json_data.keys())
