from django.conf.urls import url
from authenticate import views as Aviews
from OTPgen import views as Oviews
from django.contrib import admin

urlpatterns = [
    url(r'^(?P<api_ver>[0-9\.]{3})/(?P<auaID>[a-zA-Z0-9_]+)/(?P<uid_0>[0-9]{1})'+
	r'/(?P<uid_1>[0-9]{1})/(?P<asalk>[a-zA-Z0-9_]+)/$', Aviews.AuthMain.as_view()),

	url(r'^getLicenseKey/(?P<auaID>[a-zA-Z0-9_]+)/$',Aviews.getLicenseKey.as_view()),

	url(r'^otp/(?P<api_ver>[0-9\.]{3})/(?P<auaID>[a-zA-Z0-9_]+)/(?P<uid_0>[0-9]{1})'+
	r'/(?P<uid_1>[0-9]{1})/(?P<asalk>[a-zA-Z0-9_]+)/$', Oviews.OTPGen.as_view()),

	url(r'^admin/', admin.site.urls),
]
