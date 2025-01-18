from django.shortcuts import render

def home(request):
    return render(request, 'scarecrow/index.html')