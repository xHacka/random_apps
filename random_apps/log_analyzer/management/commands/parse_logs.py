from django.core.management.base import BaseCommand
from django.utils import timezone
from hashlib import sha256
from log_analyzer.models import LogEntry
from log_analyzer.settings import LOG_FILE_PATH, RUN_EVERY_HOUR
from urllib.parse import urlparse, parse_qs
import datetime
import re


class Command(BaseCommand):
    help = 'Parses the access.log file and stores data in the database'
    pattern = re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<timestamp>[^\]]+)\] '
        r'"(?P<method>\w+) (?P<url>[^\s]+) (?P<protocol>[^"]+)" '
        r'(?P<status>\d+) (?P<size>\d+) "(?P<referer>[^"]*)" "(?P<user_agent>[^"]+)"'
    )

    def handle(self, *args, **kwargs):
        last_entry = LogEntry.objects.order_by('-timestamp').first()
        if last_entry: # Get the timestamp of the last log entry and calculate RUN_EVERY_HOUR hours before
            cutoff_time = last_entry.timestamp - datetime.timedelta(hours=RUN_EVERY_HOUR)
        else: # If no entry exists, start from the beginning
            cutoff_time = timezone.make_aware(datetime.datetime.min)

        self.stdout.write(self.style.NOTICE(f"Parsing logs after: {cutoff_time}"))

        with open(LOG_FILE_PATH, 'r') as file:
            for line in file:
                match = self.pattern.match(line)
                if not match:
                    self.stdout.write(self.style.WARNING(f'Skipping malformed line: {line.strip()}'))
                    continue

                data = match.groupdict()
                parsed_url = urlparse(data["url"])
                data['path'] = parsed_url.path
                data['query_params'] = {k: v[0] if len(v) == 1 else v for k, v in parse_qs(parsed_url.query).items()}
                data['timestamp'] = datetime.datetime.strptime(data['timestamp'], '%d/%b/%Y:%H:%M:%S %z')
                data['status'] = int(data['status'])
                data['size'] = int(data['size'])

                if data['timestamp'] >= cutoff_time:
                    LogEntry.objects.create(
                        ip_address=data['ip'],
                        timestamp=data['timestamp'],
                        request_method=data['method'],
                        path=data['path'],
                        protocol=data['protocol'],
                        status_code=data['status'],
                        response_size=data['size'],
                        referer=data['referer'] if data['referer'] else None,
                        user_agent=data['user_agent'],
                        query_params=data['query_params'],
                    )
                else:
                    self.stdout.write(self.style.NOTICE(f'Skipping log entry: {line.strip()} (Older than 3 hours)'))

        self.stdout.write(self.style.SUCCESS('Successfully parsed log file'))
