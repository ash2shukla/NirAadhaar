from django.http import HttpResponse
from .models import AUA,ASA
from .prepareResponse import prepareResponseInit
from rest_framework.response import Response
from rest_framework.views import APIView
from json import loads
from time import time
from lxml import etree
from hashlib import sha256


class AuthMain(APIView):
	'''
	Authenticates a XML request from an ASA.
	'''
	def post(self,request,api_ver,auaID,uid_0,uid_1,asalk):
		response = prepareResponseInit(request.body,api_ver,auaID,asalk)
		return Response(response)

class getLicenseKey(APIView):
	'''
	Gives LicenseKey corresponding to a registered AUA.
	'''
	def createKey(self,auaID,current_timestamp):
		# Key valid for 3600 more seconds
		# For key validation check if the timestamp is less than the one saved in DB
		# if yes then recompute the hash and check if its same
		# If timestamp is more then ask it to getkey again
		res = sha256((auaID+str(current_timestamp+3600)).encode('utf-8')).hexdigest()
		return res

	def get(self,request,auaID):
		print(auaID)
		try:
			auaObj = AUA.objects.get(auaID__exact = auaID)
			current_timestamp = int(time())
			LK = self.createKey(auaID,current_timestamp)
			auaObj.Data['LicenseKey']= LK
			auaObj.Data['timestamp']=current_timestamp
			auaObj.save()
			return Response(LK)
		except Exception as e:
			# AUA was not registered
			return Response('NA_AUA')
