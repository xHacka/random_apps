import logging

class BaseAppRouter:
    def __init__(self, app_label, db_alias):
        self.app_label = app_label
        self.db_alias = db_alias

    def db_for_read(self, model, **hints):
        if model._meta.app_label == self.app_label:
            logging.debug(f"Routing read query for {model} to {self.db_alias}")
            return self.db_alias
        return None

    def db_for_write(self, model, **hints):
        if model._meta.app_label == self.app_label:
            logging.debug(f"Routing write query for {model} to {self.db_alias}")
            return self.db_alias
        return None
