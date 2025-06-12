from django.shortcuts import render

# Create your views here.
def quiz_view(request):
    return render(request, 'ceh12quiz/index.html')
