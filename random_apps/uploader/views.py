from django.shortcuts import render, redirect
from .models import Upload
from .forms import UploadForm
from django.views.decorators.csrf import csrf_exempt
from random_apps.decorators import admin_only
from django.core.paginator import Paginator

@csrf_exempt
def upload(request):
    if request.method == 'POST':
        form = UploadForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_item = form.save()
            request.session['filename'] = uploaded_item.title
            return redirect('upload')
    else:
        form = UploadForm()

    filename = request.session.get('filename', None)
    uploaded_file = Upload.objects.filter(title=filename).first() if filename else []

    return render(request, 'uploader/index.html', {'form': form, 'upload': uploaded_file })


@admin_only
def upload_list(request):
    def get_int_field(param, default=1):
        return int(request.GET.get(param, default))

    file_page = get_int_field('fp', 1)
    text_page = get_int_field('tp', 1)
    
    files = Upload.objects.filter(text__exact="")
    texts = Upload.objects.exclude(text__exact="")
    
    # Ensure page sizes are valid (between 1 and total count)
    file_pages = max(1, min(get_int_field('fps', 10), files.count()))
    text_pages = max(1, min(get_int_field('tps', 10), texts.count()))
    
    files = Paginator(files, file_pages).get_page(file_page)
    texts = Paginator(texts, text_pages).get_page(text_page)
    
    return render(request, 'uploader/list.html', {
        'uploads_text': texts,
        'uploads_files': files,
        'tps': text_pages,
        'fps': file_pages,
    })
    