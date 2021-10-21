from django.urls import path, include
from .views import home,result,library, unregister,about
from django.conf.urls import url
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    #path('',base,name='base'),
    path('',home,name='home'),
    path('result/', result,name='result'),
    path('library/',library,name='library'),
    path('unregister/',unregister,name='unregister'),
    path('about/',about,name='about'),
] + static(settings.MEDIA_URL, document_root = settings.MEDIA_ROOT)