#!/bin/bash

cd /var/www/random_apps/random_apps

../venv/bin/python manage.py makemigrations uploader
../venv/bin/python manage.py makemigrations b64app
../venv/bin/python manage.py makemigrations

../venv/bin/python manage.py migrate uploader --database=uploader_db
../venv/bin/python manage.py migrate b64app --database=b64app_db
../venv/bin/python manage.py migrate