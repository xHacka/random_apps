#!/bin/bash

# Variables
PROJECT_DIR="/var/www/random_apps/random_apps"
PYTHON="$PROJECT_DIR/../venv/bin/python"
NGINX_CONF_DIR="$PROJECT_DIR/conf/nginx"
NGINX_SITES_AVAILABLE="/etc/nginx/sites-available"
NGINX_SITES_ENABLED="/etc/nginx/sites-enabled"

# Go to project
cd $PROJECT_DIR

# Purge previous data
/bin/bash ./conf/scripts/cleanup.sh

# Create super user
# DJANGO_SUPERUSER_PASSWORD="x" $PYTHON manage.py createsuperuser --noinput --username x --email x@gmail.com

# Collect static files
# $PYTHON manage.py collectstatic -c --no-input

# Create uploads directory
/bin/install -m 740 -d ./log_analyzer/storage
/bin/install -m 740 -d ./uploader/storage/uploads
/bin/install -m 740 -d ./b64app/storage

# Create databases
/bin/bash ./conf/scripts/migrate.sh

# Setup cronjob for log_analyzer, every 3h
(
    sudo /bin/crontab -u www-data -l 2>/dev/null | /bin/grep -v random_apps; 
    echo "0 */3 * * * $PYTHON $PROJECT_DIR/manage.py parse_logs > $PROJECT_DIR/log_analyzer/management/commands/parse_logs.log 2>&1"
) | /bin/sudo /bin/crontab -u www-data -

# Change permissions for nginx
sudo chown -R www-data:www-data $PROJECT_DIR

# Nginx Setup
for config_file in $(ls $NGINX_CONF_DIR/*.conf); do
    config_file=$(basename $config_file)
    # Copy configuration to nginx
    echo /bin/cp "$NGINX_CONF_DIR/$config_file" "$NGINX_SITES_AVAILABLE/$config_file"
    # Enable sites
    echo /bin/ln -sf "$NGINX_SITES_AVAILABLE/$config_file" "$NGINX_SITES_ENABLED/$config_file"
done
