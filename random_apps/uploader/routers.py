from random_apps.routers import BaseAppRouter


class DBRouter(BaseAppRouter):
    def __init__(self, app_label="uploader", db_alias="uploader_db"):
        super().__init__(app_label, db_alias)
