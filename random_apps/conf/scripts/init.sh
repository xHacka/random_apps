#!/bin/bash

# Go to project
cd /var/www/random_apps_django/random_apps

# Purge previous data
bash ./conf2/scripts/cleanup.sh

# Create databases
bash ./conf2/scripts/migrate.sh

# Create super user
# DJANGO_SUPERUSER_PASSWORD="x" ../venv/bin/python manage.py createsuperuser --noinput --username x --email x@gmail.com

# Collect static files
../venv/bin/python manage.py collectstatic -c --no-input

# Change permissions for nginx
# sudo chown -R www-data:www-data ./static

# Create uploads directory
mkdir -p uploader/storage/uploads
chmod 755 uploader/storage/uploads

# Copy configuration to nginx
sudo cp ./conf2/nginx/admin.conf /etc/nginx/sites-available/random_apps_admin.conf
sudo cp ./conf2/nginx/b64app.conf /etc/nginx/sites-available/random_apps_b64app.conf
sudo cp ./conf2/nginx/scarecrow.conf /etc/nginx/sites-available/random_apps_scarecrow.conf
sudo cp ./conf2/nginx/up.conf /etc/nginx/sites-available/random_apps_up.conf

# Enable sites
sudo ln -sf /etc/nginx/sites-available/random_apps_admin.conf /etc/nginx/sites-enabled/random_apps_admin.conf
sudo ln -sf /etc/nginx/sites-available/random_apps_b64app.conf /etc/nginx/sites-enabled/random_apps_b64app.conf
sudo ln -sf /etc/nginx/sites-available/random_apps_scarecrow.conf /etc/nginx/sites-enabled/random_apps_scarecrow.conf
sudo ln -sf /etc/nginx/sites-available/random_apps_up.conf /etc/nginx/sites-enabled/random_apps_up.conf
