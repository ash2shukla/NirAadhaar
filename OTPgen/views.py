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

class OTPGen(APIView):
	'''
	Verifies the OTP request from ASA and generates OTP in SessionDB@2
	'''
	def sendmailto(self,to_id,otp,ac):
		s = SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT)
		if settings.EMAIL_USE_TLS:
			s.starttls()
		try:
			# Login to smtp server
			s.login(settings.EMAIL_HOST_USER, settings.EMAIL_HOST_PASSWORD)
			s.sendmail(settings.EMAIL_HOST_USER, to_id,'Subject: {} Has asked for your NirAadhaar OTP\n\nYour OTP is {}.\n Valid for only 5 minutes.'.format(ac,otp))
			s.quit()
			return 'SUCCESS: SENDMAIL'
		except Exception as e:
			return 'ERR: SENDMAIL'

	def sendSMSto(self,to_number,otp,ac):
		url ='http://site24.way2sms.com/Login1.action?'
		data = bytes('username=9818611161&password=123ashish&Submit=Sign+in','utf-8')
		cj= CookieJar()
		opener = build_opener(HTTPCookieProcessor(cj))
		opener.addheaders=[('User-Agent','Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.120')]
		try:
			opener.open(url, data)
		except IOError:
			return "ERR: SENDMSG"

		jession_id =str(cj).split('~')[1].split(' ')[0]
		send_sms_url = 'http://site24.way2sms.com/smstoss.action?'
		send_sms_data = bytes('ssaction=ss&Token='+jession_id+'&mobile='+to_number+'&message='+'Your Niraadhaar OTP requested by '+ac+' is '+otp+' .It will expire in 5 minutes.'+'&msgLen=136','utf-8')
		opener.addheaders=[('Referer', 'http://site25.way2sms.com/sendSMS?Token='+jession_id)]
		try:
			sms_sent_page = opener.open(send_sms_url,send_sms_data)
		except IOError:
			return "ERR: SENDMSG"

		return "SUCCESS: SENDMSG"

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

	def getInfo(self,OtpNode):
		return ''

	def prepareResponse(self,OtpNode,ret,err,code,actn=""):
		ts = self.currentISO8601()
		if OtpNode is not None:
			info = self.getInfo(OtpNode)
			txn = OtpNode.get('txn')
		else:
			info = ""
			txn = ""
		OtpResNode = self.createNode('OtpRes',['ret','code','txn','err','ts','actn','info'],[ret, code, txn, err, ts, actn, info])
		return etree.tostring(OtpResNode)

	def getResponseXML(self,OtpNodeData, ver, ac, asa):
		try:
			OtpNode = etree.fromstring(OtpNodeData)
		except Exception as e:
			ret = 'N'
			err = '999' # Could not parse to XML
			code = 'BAD_XML_OTP_NODE'
			return self.prepareResponse(None,ret,err,code)

		if not (OtpNode.get('ver') == '1.6' == ver) :
			ret = 'N'
			err = '540' # Invalid Auth XML version
			code = 'INVALID_OTP_XML_VERSION'
			return self.prepareResponse(OtpNode,ret,err,code)
			# If Authnode ac matches as of URL
		if OtpNode.get('ac') != ac:
			return self.prepareResponse(OtpNode,'N','999','MISMATCH_AC')
			# If asa matches sa
		if OtpNode.get('sa') != asa:
			return self.prepareResponse(OtpNode,'N','999','MISMATCH_SA')
		# Check if AUA can do OTP
		aua = AUA.objects.get(auaID__exact = ac)
		print(aua.Data['LicenseRights'])
		if aua.Data['LicenseRights'][6] != '1':
			return self.prepareResponse(OtpNode,'N','543','NOT_ALLOWED_TO_OTP')
		# Check what does the AUA want
		askedFor = OtpNode.find('Opts').get('ch')
		# Check if aadhaar number exists
		try:
			ResidentObj = Resident.objects.get(uid__exact = OtpNode.get('uid'))
		except Exception as e:
			# invalid aadhaar number
			return self.prepareResponse(OtpNode,'N','998','INVALID_UID')
			# Check if isVerified
		if askedFor[0] == 1 and ResidentObj.isVerified[0] == 0:
			return self.prepareResponse(OtpNode,'N','110','UID_DOES_NOT_HAVE_VERIFIED_PHONE')
		if askedFor[1] == 1 and ResidentObj.isVerified[1] == 0:
			return self.prepareResponse(OtpNode,'N','112','UID_DOES_NOT_HAVE_VERIFIED_MAIL')
		# Compute hash of uid
		uid_hash = sha256(bytes(OtpNode.get('uid'),'utf-8')).hexdigest()
		# Passed all conditions generate OTP
		otp = str(random())[2:8]
		# Save OTP in SessionDB @ 2
		s = StrictRedis(settings.SESSION_DB_URL,settings.SESSION_DB_PORT,settings.SESSION_DB)
		s.set(uid_hash,otp,ex=300) # expire in 5 minutes
		# forward to whatever it askedFor
		if askedFor[1] == '1':
			if self.sendmailto(ResidentObj.email,otp,ac) == 'ERR: SENDMAIL':
				return self.prepareResponse(OtpNode,'N','950','COULD_NOT_GENERATE_OTP_SEND_MAIL_FAIL')

		if askedFor[0] == '1':
			if self.sendSMSto(ResidentObj.phone[2:],otp,ac) == 'ERR: SENDMSG':
				return self.prepareResponse(OtpNode,'N','950','COULD_NOT_GENERATE_OTP_SEND_MSG_FAIL')

		return self.prepareResponse(OtpNode,'Y','','OK')

	def prepare_response(self,AuthNodeData, ver, ac, asalk):
		if asalk == "":
			return self.prepareResponse(None,'N','942','UNSPECIFIED_ASA_CHANNEL')
		try:
			asa = ASA.objects.get(asalk__exact=asalk)
			if ac not in asa.Data['AUAList']:
				return self.prepareResponse(None,'N','542','AUA_NOT_AUTHORIZED_BY_ASA')
		except Exception as e:
			return self.prepareResponse(None,'N','942','UNSPECIFIED_ASA_CHANNEL')
		# Check if version
		return self.getResponseXML(AuthNodeData,ver,ac,asa.asaID)

	def post(self,request,api_ver,auaID,uid_0,uid_1,asalk):
		response = self.prepare_response(request.body, api_ver, auaID, asalk)
		return Response(response)
