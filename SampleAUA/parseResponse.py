from json import loads
from lxml import etree
from Crypto.Cipher import AES
from base64 import b64decode

from .prepareRequest import skey

def decryptWithSession(data):
	iv = skey[:AES.block_size]
	cipher = AES.new(skey, AES.MODE_CBC, iv)
	decrypted = cipher.decrypt(b64decode(data))[len(iv):]
	return decrypted

def parseResponse(_type, ResponseXML):
	'''
	Parses the Response and raises Exceptions baesd on the Response Codes.
	'''
	lambdaYN = lambda x : True if x=="Y" else False

	ResponseXMLNode = etree.fromstring(ResponseXML)
	print(lambdaYN(ResponseXMLNode.get('ret')))

	if _type == "AUTH":
		if ResponseXMLNode.get('code') != "OK":
			print(ResponseXMLNode.get('code'), ResponseXMLNode.get('err'))
		return ResponseXMLNode

	elif _type == "OTP":
		if ResponseXMLNode.get('code') != "OK":
			print(ResponseXMLNode.get('code'), ResponseXMLNode.get('err'))
		return ResponseXMLNode

	elif _type == "KYC":
		if ResponseXMLNode.get('code') != "OK":
			print(ResponseXMLNode.get('code'), ResponseXMLNode.get('err'))
		response = decryptWithSession(ResponseXMLNode.text).split(b'</KycRes>')[0]+b'</KycRes>'
		KycResNode = etree.fromstring(response)
		return KycResNode
