from .models import LogEntry
from datetime import timedelta
from django.db.models import Count, Sum, Avg
from django.db.models import Q
from django.db.models.functions import TruncDay 
from django.http import JsonResponse
from django.utils import timezone
from django.views.generic import TemplateView
from log_analyzer.models import LogEntry 
import json

class DashboardView(TemplateView):
    template_name = 'log_analyzer/dashboard.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        # Time range for analytics
        end_date = timezone.now()
        start_date = end_date - timedelta(days=7)
        
        # Daily traffic
        daily_traffic = (
            LogEntry.objects.filter(timestamp__range=(start_date, end_date))
            .annotate(day=TruncDay('timestamp'))
            .values('day')
            .annotate(requests=Count('id'), avg_response_size=Avg('response_size'))
            .order_by('day')
        )

        # HTTP methods distribution
        http_methods = (
            LogEntry.objects.values('request_method')
            .annotate(count=Count('id'))
            .order_by('-count')
        )

        # Status code distribution
        status_codes = (
            LogEntry.objects.values('status_code')
            .annotate(count=Count('id'))
            .order_by('-count')
        )

        # Top paths
        top_paths = (
            LogEntry.objects.values('path')
            .annotate(count=Count('id'))
            .order_by('-count')[:10]
        )

        # Top IPs
        top_ips = (
            LogEntry.objects.values('ip_address')
            .annotate(
                requests=Count('id'),
                total_bytes=Sum('response_size')
            )
            .order_by('-requests')[:10]
        )

        context.update({
            'daily_traffic': json.dumps(list(daily_traffic), default=str),
            'http_methods': json.dumps(list(http_methods), default=str),
            'status_codes': json.dumps(list(status_codes), default=str),
            'top_paths': top_paths,
            'top_ips': top_ips,
        })
        return context

class FilterView(TemplateView):
    template_name = 'log_analyzer/filter.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        fields = [
            {'name': 'ip_address', 'type': 'text', 'label': 'IP Address'},
            {'name': 'request_method', 'type': 'choice', 'choices': LogEntry.objects.values_list('request_method', flat=True).distinct()},
            {'name': 'path', 'type': 'text', 'label': 'Path'},
            {'name': 'status_code', 'type': 'number', 'label': 'Status Code'},
            {'name': 'date', 'type': 'date', 'label': 'Date'},
        ]
        context['fields'] = fields
        return context

def filter_logs(request):
    filters = Q()

    for key, value in request.GET.items():
        if value and key != 'page':
            if key == 'date':
                try:
                    date = timezone.datetime.strptime(value, '%Y-%m-%d')
                    filters &= Q(timestamp__date=date)
                except ValueError:
                    pass
            elif key == 'ip_address':
                filters &= Q(ip_address__icontains=value)  # Fuzzy search for IP
            elif key == 'path':
                filters &= Q(path__icontains=value)  # Fuzzy search for Path
            else:
                filters &= Q(**{key: value})

    queryset = LogEntry.objects.filter(filters)
    
    # Pagination
    page = int(request.GET.get('page', 1))
    per_page = 50
    start = (page - 1) * per_page
    end = start + per_page
    
    data = list(queryset[start:end].values())
    total = queryset.count()
    
    return JsonResponse({
        'data': data,
        'total': total,
        'pages': (total + per_page - 1) // per_page
    })
    
