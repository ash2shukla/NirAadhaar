from django.conf.urls import url
from authenticate import views
from django.contrib import admin

urlpatterns = [
    url(r'^(?P<api_ver>[0-9\.]{3})/(?P<asaID>[a-zA-Z0-9]+)/(?P<uid_0>[0-9]{1})'+
	r'/(?P<uid_1>[0-9]{1})/(?P<asalk>[a-zA-Z0-9_]+)$', views.AuthMain.as_view()),
	url(r'^getLicenseKey/(?P<auaID>[a-zA-Z0-9_]+)$',views.getLicenseKey.as_view()),
    url(r'^admin/', admin.site.urls),
]
