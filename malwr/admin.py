from django.contrib import admin

# Register your models here.
from .models import DataMalware,UploadSample

class adminData(admin.ModelAdmin):
    list_display = ('md5', 'type')

admin.site.register(DataMalware, adminData,)
admin.site.register(UploadSample)
