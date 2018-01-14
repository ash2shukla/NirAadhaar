from django.http import HttpResponse
from .models import AUA,ASA
from .prepareResponse import prepare_response
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
				# Check if asalk matches that of asaObj
				if asaObj.asalk == asalk:
					# Request is Authentic
					#try:
						response = prepare_response(etree.fromstring(request.body))
						return Response(response)
					#except:
					#	return Response('BAD_XML')
				else:
					# ASALK does not match
					return Response('NM_ASALK')
			else:
				# ASA does not exist
				return Response('NA_ASA')
		else:
			# API Version Mismatch
			return Response('APIERR')

class getLicenseKey(APIView):
	'''
	Gives LicenseKey corresponding to a registered ASA.
	'''
	def createKey(self,auaID,current_timestamp):
		# Key valid for 3600 more seconds
		# For key validation check if the timestamp is less than the one saved in DB
		# if yes then recompute the hash and check if its same
		# If timestamp is more then ask it to getkey again
		res = sha256((auaID+str(current_timestamp+3600)).encode('utf-8')).hexdigest()
		return res

	def get(self,request,auaID):
		try:
			auaObj = AUA.objects.get(auaID__exact = auaID)
			current_timestamp = int(time())
			LK = self.createKey(auaID,current_timestamp)
			auaObj.Data['LicenseKey']= LK
			auaObj.Data['timestamp']=current_timestamp
			auaObj.save()
			return Response(LK)
		except:
			# AUA was not registered
			return Response('NA_AUA')
