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
from base64 import b64decode, b64encode
from django.conf import settings
from smtplib import SMTP
from urllib.request import HTTPCookieProcessor,build_opener
from http.cookiejar import CookieJar
from authenticate.prepareResponse import encryptWithSkey, getResponseXML as Auth_getResponseXML

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

	def getInfo(self,KycNode):
		return ""

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

	def prepareResponseNode(self,KycNode, AuthResData, ret,err,code,actn=""):
		ts = self.currentISO8601()

		if KycNode is not None:
			info = self.getInfo(KycNode)
			txn = KycNode.get('txn')
		else:
			info = ""
			txn = ""

		AuthNode = etree.fromstring(b64decode(KycNode.text))
		auaRights = AUA.objects.get(auaID__exact = AuthNode.get('ac')).Data['LicenseRights']
		AuthResNode = etree.fromstring(AuthResData)

		ko ='KUA' if KycNode.get('de') == 'Y' else 'KSA'
		ret,status,err,code = ('Y','0','','OK') if AuthResNode.get('ret') == 'Y' else ('N','-1','K-100','RESIDENT_AUTHENTICATION_FAILED')


		if status == '0':
			try:
				# Get Resident information
				ResidentObj = Resident.objects.get(uid__exact = AuthNode.get('uid'))
			except:
				err,status,err,code='N','-1','K-200','RESIDENT_INFO_NOT_AVAILABLE'
		else:
			ResidentObj = None

		RespNode = self.createNode('Resp',['status','ko','ret','code','txn','ts','err'],[status, ko, ret, code, txn, ts, err])

		KycResNode = self.createNode('KycRes',['ret','code','txn','ts','ttl','actn','err'],[ret,code,txn,ts,"300",actn,err])
		RarNode = self.createNode('Rar',[],[], AuthResData)

		# get Poi
		if ResidentObj is not None:
			uid = ResidentObj.uid
			name = ResidentObj.name
			dob = ResidentObj.dob
			gender = ResidentObj.gender
			phone = ResidentObj.phone
			email = ResidentObj.email
		else:
			uid = ""
			name = ""
			dob= ""
			gender = ""
			phone = ""
			email = ""

		#get Poa
		PoaElements = ['lm','pc','po','loc','vtc','dist','house','state','street','subdist','country']
		if ResidentObj is not None:
			PoaValues = []
			for i in PoaElements:
				PoaValues.append(ResidentObj.address[i])
			PoaElements.append('co')
			PoaValues.append(ResidentObj.care_of)
		else:
			PoaElements.append('co')
			PoaValues = ['','','','','','','','','','','']

		#get LData
		LDataElements = ['lang','name','co','house','street','lm','loc','vtc','subdist','dist','state','pc','po','country']
		if (ResidentObj is not None) and (auaRights[9]=='1'):
			LDataValues = []
			LDataValues.append(ResidentObj.lang_code)
			LDataValues.append(ResidentObj.lname)
			LDataValues.append(ResidentObj.lcare_of)
			for i in LDataElements[3:]:
				LDataValues.append(ResidentObj.laddress[i])
		else:
			LDataValues = ['','','','','','','','','','','','','','']

		if ResidentObj is not None:
			photo = b64encode(open(ResidentObj.photo.path,'rb').read())
		else:
			photo = ""

		UidData = self.createNode('Uid',['uid'],[uid])
		PoiNode = self.createNode('Poi',['name','dob','gender','phone','email'],[name,dob,gender,phone,email])
		PoaNode = self.createNode('Poa',PoaElements, PoaValues)
		LDataNode = self.createNode('LData',LDataElements,LDataValues)
		PhtNode = self.createNode('Pht',[],[],photo)
		PrnNode = self.createNode('Prn',['type'],['pdf'],"")

		KycResNode.append(RarNode)

		UidData.append(PoiNode)
		UidData.append(PoaNode)
		UidData.append(LDataNode)
		UidData.append(PhtNode)
		UidData.append(PrnNode)

		KycResNode.append(UidData)

		KycResEncrypted = encryptWithSkey(AuthNode,etree.tostring(KycResNode))

		RespNode.text = KycResEncrypted

		return etree.tostring(RespNode)

	def getResponseXML(self, KycNodeData, ver, ac, asa):
		try:
			KycNode = etree.fromstring(KycNodeData)
		except Exception as e:
			ret = 'N'
			err = 'K-540' # Could not parse to XML
			code = 'INVALID_KYC_XML'
			return self.prepareResponseNode(None,b'',ret,err,code)

		if not (KycNode.get('ver') == '2.0' == ver) :
			ret = 'N'
			err = 'K-541' # Invalid Auth XML version
			code = 'INVALID_KYC_XML_VERSION'
			return self.prepareResponseNode(KycNode,b'',ret,err,code)
			# If Authnode ac matches as of URL

		AuthResponseNode = Auth_getResponseXML(b64decode(KycNode.text), ver, ac, asa,True)

		return self.prepareResponseNode(KycNode,AuthResponseNode,'Y','','OK')

	def prepareResponseInit(self,KycNodeData, ver, ac, asalk):
		if asalk == "":
			return self.prepareResponseNode(None,b'','N','K-601','UNSPECIFIED_ASA_CHANNEL')
		try:
			asa = ASA.objects.get(asalk__exact=asalk)
			if ac not in asa.Data['AUAList']:
				return self.prepareResponseNode(None,b'','N','K-600','AUA_NOT_AUTHORIZED_BY_ASA')
		except Exception as e:
			return self.prepareResponseNode(None,b'','N','K-601','UNSPECIFIED_ASA_CHANNEL')

		return self.getResponseXML(KycNodeData,ver,ac,asa.asaID)

	def post(self,request,api_ver,auaID,uid_0,uid_1,asalk):
		response = self.prepareResponseInit(request.body, api_ver, auaID, asalk)
		return Response(response)
