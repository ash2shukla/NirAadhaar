from sys import version_info
from json import load
from os import path
from lxml import etree
from hashlib import sha256
from base64 import b64encode,b64decode
from lxml import etree

from .parseResponse import parseResponse
from .prepareRequest import populateAuthXML, populateKYCXML, populateOTPXML
from .prepareRequest import AuthRes, KycRes, OTPRes
from .config import *

from urllib.request import Request, urlopen
from urllib.parse import urlencode

# Use RAWresponse for whole XML

def AuthInit(JSONInfo,otp=""):
	AuthXML = populateAuthXML(JSONInfo,otp)
	RAWresponse = AuthRes(AuthXML)

	return parseResponse('AUTH',RAWresponse)

def OTPInit(ch,uid):
	"""
	ch = 00 01 10 11, <phone><email>
	uid
	"""
	OTPXML = populateOTPXML(ch,uid)
	RAWresponse = OTPRes(uid,OTPXML)

	return parseResponse('OTP',RAWresponse)

def eKYCInit(JSONInfo,otp=""):
	AuthXML = populateAuthXML(JSONInfo,otp,for_KYC=True)
	AuthXMLb64 = b64encode(AuthXML)
	KYCXML = populateKYCXML(AuthXMLb64)
	RAWresponse = KycRes(KYCXML,JSONInfo['uid'])

	return parseResponse('KYC', RAWresponse)

def GetAttribute(ResponseXMLNode, attribute):
	pass


if __name__ == "__main__":
	JSONInfo = load(open('Input.json','r'))
	#OTPInit("11",JSONInfo['uid'])
	#AuthInit(JSONInfo,"402521")
	eKYCInit(JSONInfo,"402521")
