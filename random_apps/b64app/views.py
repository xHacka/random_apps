from . import settings
from .models import EncodedEntry, DecodedEntry
from django.http import JsonResponse
from django.shortcuts import render
from random_apps.decorators import admin_only
import base64
from django.views.decorators.csrf import csrf_exempt

MAX_SIZE = getattr(settings, 'MAX_SIZE', 1000)


def index(request):
    # return render(request, 'b64app/index.html', {
    return render(request, 'b64app/index2.html', {
        'encoded': request.session.get('encoded'),
        'decoded': request.session.get('decoded')
    })


@csrf_exempt
def encode(request):
    if request.method != 'POST':
        return JsonResponse({"error": "Method not allowed", "result": None}, status=400)

    data: bytes = request.POST.get('data', '').encode('utf-8')
    if len(data) > MAX_SIZE:
        return JsonResponse({"error": "Data exceeds the maximum allowed size of 3.2MB.", "result": None}, status=400)

    if len(data.strip()) < 1:
        return JsonResponse({"error": f"Only spaces not allowed", "result": None}, status=400)

    result = base64.b64encode(data).decode('utf-8')
    request.session['encoded'] = result

    if getattr(settings, 'SAVE_TO_DB', False):
        EncodedEntry.objects.create(original=data.decode(), converted=result)

    return JsonResponse({"error": None, "result": result})


@csrf_exempt
def decode(request):
    if request.method != 'POST':
        return JsonResponse({"error": "Method not allowed", "result": None}, status=400)

    data: bytes = request.POST.get('data', '').encode('utf-8')
    if len(data) > MAX_SIZE:
        return JsonResponse({"error": "Data exceeds the maximum allowed size of 3.2MB.", "result": None}, status=400)

    if len(data.strip()) < 1:
        return JsonResponse({"error": f"Only spaces not allowed"}, status=400)

    try:
        data = data + b'=='
        result = base64.b64decode(data).decode('utf-8')
        request.session['decoded'] = result
    except Exception as e:
        return JsonResponse({"error": f"Invalid Base64 data: {str(e)}"}, status=400)

    if getattr(settings, 'SAVE_TO_DB', False):
        DecodedEntry.objects.create(original=data.decode(), converted=result)

    return JsonResponse({"error": None, "result": result})


@admin_only
def show_encoded(request):
    records = EncodedEntry.objects.all()
    return render(request, 'b64app/table.html', {'title': 'Encoded Data', 'records': records})

@admin_only
def show_decoded(request):
    records = DecodedEntry.objects.all()
    return render(request, 'b64app/table.html', {'title': 'Decoded Data', 'records': records})
