cd WORKSPACE

Get-ChildItem -Directory -Recurse -Filter '__py*' | Remove-Item -Force -Recurse
Get-ChildItem -Directory -Recurse -Filter 'migr*' | Remove-Item -Force -Recurse
Get-ChildItem -Directory -Recurse -Filter 'uploads' | Remove-Item -Force -Recurse
Get-ChildItem -File -Recurse -Filter 'db.sqlite3' | Remove-Item -Force -Recurse

..\venv\Scripts\python.exe manage.py makemigrations log_analyzer
..\venv\Scripts\python.exe manage.py makemigrations uploader
..\venv\Scripts\python.exe manage.py makemigrations b64app
..\venv\Scripts\python.exe manage.py makemigrations

..\venv\Scripts\python.exe manage.py migrate log_analyzer --database=log_analyzer_db
..\venv\Scripts\python.exe manage.py migrate uploader --database=uploader_db
..\venv\Scripts\python.exe manage.py migrate b64app --database=b64app_db
..\venv\Scripts\python.exe manage.py migrate

$ENV:DJANGO_SUPERUSER_PASSWORD="x"
..\venv\Scripts\python.exe manage.py createsuperuser --noinput --username x --email x@gmail.com

New-Item -Type Directory -Path .\log_analyzer -Force -ErrorAction SilentlyContinue
New-Item -Type Directory -Path .\uploader\storage\uploads -Force -ErrorAction SilentlyContinue
New-Item -Type Directory -Path .\b64app\storage -Force -ErrorAction SilentlyContinue