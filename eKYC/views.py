from django.http import HttpResponse
from authenticate.models import AUA,ASA,Resident
from rest_framework.response import Response
from rest_framework.views import APIView
from json import loads
from time import time
from datetime import datetime
from lxml import etree
from hashlib import sha256
from random import random
from redis import StrictRedis
from django.conf import settings
from smtplib import SMTP
from urllib.request import HTTPCookieProcessor,build_opener
from http.cookiejar import CookieJar

class eKYCMain(APIView):
	'''
	Verifies the eKYC request from ASA.
	'''

	def currentISO8601(self):
		'''
		Returns current time stamp in ISO8601 format YYYY:MM:DDTHH:MM:SS
		'''
		now_ist = datetime.now()
		year = str(now_ist.year)
		month = str(now_ist.month)
		day = str(now_ist.day)
		hour = str(now_ist.hour)
		minute = str(now_ist.minute)
		second = str(now_ist.second)

		if len(month) == 1:
			month = '0'+month

		if len(day) == 1:
			day = '0'+day

		date = '-'.join([year,month,day])
		_time = ':'.join([hour,minute,second])

		return date+"T"+_time

	def createNode(self,nodeName, elements, values,text = None):
		'''
		Creates one XML node for given elements and their values and the text.
		'''
		node = etree.Element(nodeName)
		for i,j in zip(elements,values):
			if j is not None:
				node.set(i,j)
		if text is not None:
			node.text = text
		return node

	def isSignatureValid(DS):
		if DS is None:
			return False
		else:
			DS = '-----BEGIN CERTIFICATE-----\n'+DS+'\n-----END CERTIFICATE-----'
			DS_bytes = bytes(DS,'utf-8')
			return verify_chain(settings.CERT_CHAIN_PATH, DS_bytes)

	def getInfo(self,KycNode):
		return ''

	def prepareResponseNode(self,KycNode,ret,err,code,actn=""):
		ts = self.currentISO8601()
		if KycNode is not None:
			info = self.getInfo(KycNode)
			txn = KycNode.get('txn')
		else:
			info = ""
			txn = ""
		KycResNode = self.createNode('KycRes',['ret','code','txn','err','ts','actn','info'],[ret, code, txn, err, ts, actn, info])
		return etree.tostring(KycResNode)

	def getResponseXML(self,KycNodeData, ver, ac, asa):
		try:
			KycNode = etree.fromstring(KycNodeData)
		except Exception as e:
			ret = 'N'
			err = '999' # Could not parse to XML
			code = 'BAD_XML_KYC_NODE'
			return self.prepareResponseNode(None,ret,err,code)


		if not (KycNode.get('ver') == '2.0' == ver) :
			ret = 'N'
			err = '540' # Invalid Auth XML version
			code = 'INVALID_KYC_XML_VERSION'
			return self.prepareResponseNode(KycNode,ret,err,code)
			# If Authnode ac matches as of URL

		return self.prepareResponseNode(KycNode,'Y','','OK')

	def prepare_response(self,KycNodeData, ver, ac, asalk):
		if asalk == "":
			return self.prepareResponseNode(None,'N','942','UNSPECIFIED_ASA_CHANNEL')
		try:
			asa = ASA.objects.get(asalk__exact=asalk)
			if ac not in asa.Data['AUAList']:
				return self.prepareResponseNode(None,'N','542','AUA_NOT_AUTHORIZED_BY_ASA')
		except Exception as e:
			return self.prepareResponseNode(None,'N','942','UNSPECIFIED_ASA_CHANNEL')
		# Check if version
		return self.getResponseXML(KycNodeData,ver,ac,asa.asaID)

	def post(self,request,api_ver,auaID,uid_0,uid_1,asalk):
		response = self.prepare_response(request.body, api_ver, auaID, asalk)
		return Response(response)
