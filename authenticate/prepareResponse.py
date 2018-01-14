from lxml import etree
from datetime import datetime
from hashlib import sha256
from django.conf import settings
from os import path
from .models import ASA,AUA
from OpenSSL.crypto import load_privatekey, FILETYPE_PEM
from base64 import b64decode

def createNode(nodeName, elements, values,text = None):
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

def isValid(AuthNode):
	return 'Y'

def getAuthCode(AuthNode):
	# Max Length AuthCode = 40
	return 'LEL'

def getTxnID(AuthNode):
	return AuthNode.get('txn')

def currentISO8601():
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

def decryptData(AuthNode):
	lk = AuthNode.get('lk')
	# Check who was assigned this lk  in ASA
	try:
		AuaObj = AUA.objects.get(Data__contains = {"LicenseKey":lk})
		pk_bytes = b64decode(AuaObj.Data['privateKey'].encode('utf-8'))
		pk_pass = AuaObj.Data['pkPass']
		print(pk_pass)
		#print(load_privatekey(FILETYPE_PEM, pk_bytes,passphrase=pk_pass))
	except:
		return 'ERR: LKEY_NOT_FOUND'

def getAction(AuthNode):
	# Return action code if required
	return ''

def getInfo(AuthNode):
	# Meta Autentication information
	version = '02'
	hm = sha256(bytes(AuthNode.get('uid'),'utf-8')).hexdigest()
	return ''

def prepare_response(AuthNode):
	# Check if the request is valid or not
	try:
		ret,err = isValid(AuthNode)
		code = "OK"
	except:
		# If Request could not be parsed
		ret = 'N'
		code = "NA"
		err = '999'
	if decryptData(AuthNode) == 'ERR: LKEY_NOT_FOUND':
		ret = 'N'
		code = 'NA'
		err = '566'

	ts = currentISO8601()
	info = getInfo(AuthNode)
	txn = getTxnID(AuthNode)

	SignatureNode = createNode('Signature',['xmlns'],['http://www.w3.org/2000/09/xmldsig#'])
	SignedInfoNode = createNode('SignedInfo',[],[])
	CanonicalizationMethodNode = createNode('CanonicalizationMethod',['Algorithm'],['http://www.w3.org/TR/2001/REC-xml-c14n-20010315'])
	SignatureMethodNode = createNode('SignatureMethod',['Algorithm'],['http://www.w3.org/2000/09/xmldsig#rsa-sha256'])
	ReferenceNode = createNode('Reference',['URI'],[''])
	TransformsNode = createNode('Transforms',[],[])
	TransformNode = createNode('Transform',['Algorithm'],["http://www.w3.org/2000/09/xmldsig#enveloped-signature"])
	DigestMethodNode = createNode('DigestMethod',['Algorithm'],["http://www.w3.org/2000/09/xmldsig#sha256"])
	DigestValueNode = createNode('DigestValue',[],[])
	SignatureValueNode = createNode('SignatureValue',[],[])
	return 'Response lele'
