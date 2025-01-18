cd 'C:\Users\pvpga\VBoxShare\random_apps_django\random_apps'

ls -rec -fil __py* | rm -rec
ls -rec -fil migr* | rm -rec
ls -rec -fil db.sqlite3 | rm -rec
ls -rec -fil uploads | ls | rm -force

..\venv\Scripts\python.exe manage.py makemigrations
..\venv\Scripts\python.exe manage.py makemigrations b64app
..\venv\Scripts\python.exe manage.py makemigrations uploader

..\venv\Scripts\python.exe manage.py migrate
..\venv\Scripts\python.exe manage.py migrate b64app --database=b64app_db
..\venv\Scripts\python.exe manage.py migrate uploader --database=uploader_db

$env:DJANGO_SUPERUSER_PASSWORD="x"
..\venv\Scripts\python.exe manage.py createsuperuser --noinput --username x --email x@gmail.com
