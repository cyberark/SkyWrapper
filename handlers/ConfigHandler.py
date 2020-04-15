import yaml
from exceptions.SingletonClassException import SingletonClassException
from utilities.FileUtilities import get_project_root
import os

class ConfigHandler(object):
    __instance = None

    @staticmethod
    def get_instance():
        """ Static access method. """
        if ConfigHandler.__instance == None:
            ConfigHandler()
        return ConfigHandler.__instance

    def __init__(self):
        """ Virtually private constructor. """
        if ConfigHandler.__instance != None:
            raise SingletonClassException("This class is a singleton!")
        else:
            self.config = self.__load_config_file()
            ConfigHandler.__instance = self

    def __load_config_file(self):
        config_path = os.path.join(get_project_root(), "config.yml")
        with open(config_path, 'r') as yaml_config:
            config = yaml.load(yaml_config, Loader=yaml.FullLoader)
        return config

    def get_config(self):
        return self.config

    def save_config(self):
        config_path = os.path.join(get_project_root(), "config.yml")
        with open(config_path, 'w') as yaml_config:
            yaml.dump(self.config, yaml_config, default_flow_style=False)