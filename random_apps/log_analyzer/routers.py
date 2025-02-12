from random_apps.routers import BaseAppRouter


class DBRouter(BaseAppRouter):
    def __init__(self, app_label="log_analyzer", db_alias="log_analyzer_db"):
        super().__init__(app_label, db_alias)
