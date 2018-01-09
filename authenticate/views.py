from django.http import HttpResponse
from .models import AUA,ASA
from .prepareResponse import prepare_response
from rest_framework.response import Response
from rest_framework.views import APIView
from json import loads
from time import time
from hashlib import sha256

class AuthMain(APIView):
	def post(self,request,api_ver,asaID,uid_0,uid_1,asalk):
		if api_ver == '1.6':
			# uid_0 and uid_1 are only used for load balancing which we don't
			# require to do at the moment
			#Check if auaID exists
			try:
				asaObj = ASA.objects.get(asaID__exact=asaID)
			except:
				asaObj = None

			if asaObj is not None:
				# ASA req is authentic
				if 'data' in request.data.keys():
					# Write logic to parse the request
					# Create Response if request is Okay
					response = prepare_response()
					return Response(response)
				else:
					# Data isn't posted.
					return Response('NA_DATA')
			else:
				# ASAID does not exist
				return Response('NA_ASA')
		else:
			# API Version Mismatch
			return Response('APIERR')

class getLicenseKey(APIView):
	def createKey(self,asaID,current_timestamp):
		# Key valid for 3600 more seconds
		# For key validation check if the timestamp is less than the one saved in DB
		# if yes then recompute the hash and check if its same
		# If timestamp is more then ask it to getkey again
		res = sha256((asaID+str(current_timestamp+3600)).encode('utf-8')).hexdigest()
		return res

	def get(self,request,asaID):
		try:
			asaObj = ASA.objects.get(asaID__exact = asaID)
			current_timestamp = int(time())
			LK = self.createKey(asaID,current_timestamp)
			asaObj.Data['LicenseKey']= LK
			asaObj.Data['timestamp']=current_timestamp
			asaObj.save()
			return Response(LK)
		except:
			# AUA was not registered
			return Response('NA_AUA')
