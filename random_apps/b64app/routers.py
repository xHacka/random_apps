from random_apps.routers import BaseAppRouter


class DBRouter(BaseAppRouter):
    def __init__(self, app_label="b64app", db_alias="b64app_db"):
        super().__init__(app_label, db_alias)
