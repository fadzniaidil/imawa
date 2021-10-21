from django.shortcuts import render,redirect, HttpResponse
from django.views.generic import TemplateView, ListView
from .models import DataMalware,UploadSample
from django.db.models import Q
from django.core.files.storage import FileSystemStorage
from .CheckingFile import checkpre,hashcheck,savestorage, procedureXK001, sample_extraction, db_saving
import os

# Create your views here.
#def base(request):
#	return render(request,'malwr/base.html')
fs = FileSystemStorage(location = os.path.join(os.path.dirname(os.path.realpath(__file__)))+'/media')

def home(request):
	if request.method == 'POST':
		file2 = request.FILES['files']
		#document = FileUpload.objects.create(file=file2)
		#document.save()
		filename = fs.save(file2.name,file2)
		data = fs.url(filename)
		check = hashcheck(data)
		query_check = DataMalware.objects.filter(md5 = check)
		result = checkpre(data)
		simp = sample_extraction(data)

		
		if query_check.exists():
			xkclass = procedureXK001(data)
			savestorage(data)
			return render(request,"malwr/register.html",{"result":query_check,'xkclass':xkclass})
		elif result == 'Malicious':
			xkclass = procedureXK001(data)
			db_saving(data)
			savestorage(data)
			return render(request,'malwr/unregister.html',{'result':result ,'xkclass':xkclass, 'simp':simp})
		else :
			db_saving(data)
			savestorage(data)
			return render(request,'malwr/unregister.html',{'result':result, 'simp':simp})

	else:
		return render(request,'malwr/home.html')

def result(request):
	query = request.GET.get('q')
	result = DataMalware.objects.filter(Q(md5__icontains=query)|Q(sha1__icontains=query)|Q(sha256__icontains=query))
	return render(request,'malwr/search.html',{'result':result})

def library(response):
	data = DataMalware.objects.all()
	
	return render(response,'malwr/library.html',{'data':data})

def unregister(response):
	return render(response,'malwr/unregister.html')

def about(response):
	return render(response,'malwr/about.html')