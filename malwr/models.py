from djongo import models
from django.core.files.storage import FileSystemStorage

fs = FileSystemStorage(location='/media/sample')

class DataMalware(models.Model):

    id = models.TextField(primary_key=True)  # This field type is a guess.
    dataSize = models.CharField(max_length=255)
    arch = models.IntegerField()
    md5 = models.CharField(max_length=255)
    sha1 = models.CharField(max_length=255)
    sha256 = models.CharField(max_length=255)
    timestamp = models.CharField(max_length=255)
    status = models.CharField(max_length=255)
    type = models.CharField(max_length=255)

    def __str__(self):
    	return self.md5

class UploadSample(models.Model):
	file = models.FileField(upload_to='media/')