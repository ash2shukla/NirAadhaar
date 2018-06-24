from lxml import etree
from datetime import datetime
from hashlib import sha256
from django.conf import settings
from os import path
from .models import ASA,AUA,Resident
from OpenSSL.crypto import load_privatekey, FILETYPE_PEM, load_certificate
from base64 import b64decode,b64encode
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random
from re import sub
from Levenshtein import jaro
from redis import StrictRedis
from OpenCA import verify_chain

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

def encryptWithSkey(AuthNode, text):
	_AES256key = decryptSkey(AuthNode)

	if ((_AES256key != "") and (text !="")):
		padded = text + bytes((32 - len(text) % 32) * chr(32 - len(text) % 32),'utf-8')
		iv = Random.new().read(AES.block_size)
		cipher = AES.new(_AES256key, AES.MODE_CBC, iv)
		return b64encode(iv + cipher.encrypt(padded))

def decryptSkey(AuthNode):
	aua = AuthNode.get('ac')
	# Check who was assigned this lk  in ASA
	AuaObj = AUA.objects.get(auaID__exact=aua)
	pk_bytes = b64decode(AuaObj.Data['privateKey'].encode('utf-8'))
	pk_pass = AuaObj.Data['pkPass']
	pk = RSA.importKey(pk_bytes)
	skey_bytes = AuthNode.find('Skey').text
	return pk.decrypt(b64decode(skey_bytes))

def getLicenseRights(AuthNode):
	aua = AuthNode.get('ac')
	AuaObj = AUA.objects.get(auaID__exact = aua)
	return AuaObj.Data['LicenseRights']

def decryptWithSession(skey,data):
	iv = skey[:AES.block_size]
	cipher = AES.new(skey, AES.MODE_CBC, iv)
	decrypted = cipher.decrypt(b64decode(data))[len(iv):]
	return decrypted

def fuzzyStr(perc, str_one, str_two ):
	if all(i in str_two.split() for i in str_one.split()):
		return True
	try:
		perc = int(perc)
	except:
		return False
	if int(jaro(str_one,str_two)*100) >= perc:
		return True
	else:
		return False


def getInfo(AuthNode):
	# Meta Autentication information
	version = '02'
	hm = sha256(bytes(AuthNode.get('uid'),'utf-8')).hexdigest()
	return ''

def isLicenseValid(AuthNode):
	# Get Current LicenseKey for AC
	if AUA.objects.get(auaID__exact = AuthNode.get('ac')).Data['LicenseKey'] != AuthNode.get('lk'):
		return False
	return True

def isCIValid(AuthNode):
	ci = AuthNode.find('Skey').get('ci')

	if ci is None:
		return False
	else:
		# Load certificate
		DS = '-----BEGIN CERTIFICATE-----\n'+AuthNode.find('Signature').text+'\n-----END CERTIFICATE-----'
		cert = load_certificate(FILETYPE_PEM,bytes(DS,'utf-8'))
		if ci != cert.get_notAfter().decode('utf-8'):
			return False
		return True

def isSignatureValid(DS):
	if DS is None:
		return False
	else:
		DS = '-----BEGIN CERTIFICATE-----\n'+DS+'\n-----END CERTIFICATE-----'
		DS_bytes = bytes(DS,'utf-8')
		return verify_chain(settings.CERT_CHAIN_PATH, DS_bytes)

def ISOToDatetime(ts):
	parts = ts.split('T')
	parts_0 = parts[0].split('-')
	parts_1 = parts[1].split(':')
	return datetime(int(parts_0[0]),int(parts_0[1]),int(parts_0[2]),int(parts_1[0]),int(parts_1[1]),int(parts_1[2]))

def ISOTimeDiff(ts1,ts2):
	return int(abs(ISOToDatetime(ts1) - ISOToDatetime(ts2)).total_seconds())

def isUsesPidValid(UsesNode, PIDNode, Rights, ResidentObj):
	if ISOTimeDiff(PIDNode.get('ts'),currentISO8601()) >300: # If request is older than 5 mins
		return 'N','561','REQUEST_EXPIRED'
	valid_dict = {
	'IIR':['LEFT_IRIS','RIGHT_IRIS'],\
	'FMR':['LEFT_THUMB','RIGHT_THUMB','LEFT_INDEX','RIGHT_INDEX','LEFT_LITTLE','RIGHT_LITTLE','LEFT_RING','RIGHT_RING','LITTLE_MIDDLE','RIGHT_MIDDLE'],\
	'FIR':['LEFT_THUMB','RIGHT_THUMB','LEFT_INDEX','RIGHT_INDEX','LEFT_LITTLE','RIGHT_LITTLE','LEFT_RING','RIGHT_RING','LITTLE_MIDDLE','RIGHT_MIDDLE']}

	lambdayn = lambda x: True if x=='Y' else False

	lambda10 = lambda x: True if x=='1' else False
	match_l = False # match Local attributes
	# Check language
	if PIDNode.find('Demo').get('lang') != "":
		# Check if it is allowed to access language
		if not lambda10(Rights[9]):
			return 'N','582','LOCAL_LANGUAGE_NOT_ALLOWED' # Local Language use not allowed
		elif PIDNode.find('Demo').get('lang') != ResidentObj.lang_code:
			return 'N','568','LANGUAGE_NOT_SUPPORTED' # Language code does not match Unsupported Language
		match_l = True

	PiNode = PIDNode.find('Demo').find('Pi')
	# Asked for pi but in Usage but not allowed
	if lambdayn(UsesNode.get('pi')):
		if (not lambda10(Rights[0])):
			return 'N','573','NOT_ALLOWED_TO_PI' # Not allowed to PI
		if PiNode is None:
			return 'N','710','NO_VALUES_FOR_PI' # Not given PI
		if PiNode.get('ms') == 'P':
			# If fuzzy matching is expected check if it is allowed
			if not lambda10(Rights[8]):
				return 'N','581','NOT_ALLOWED_FUZZY_MATCHING_PI' # Fuzzy matching not allowed
			else:
				perc = PiNode.get('mv')
				lperc = PiNode.get('lmv')
				# match name this much
				if not fuzzyStr(perc,PiNode.get('name'), ResidentObj.name):
					return 'N','100','PI_NOT_MATCH_NAME_FUZZY' # Pi attributes did not match
				if match_l:
					if not fuzzyStr(lperc, PiNode.get('lname'), ResidentObj.lname):
						return 'N','100','PI_NOT_MATCH_LNAME_FUZZY' # Pi attributes did not match
		else:
			# Exact match of names
			if PiNode.get('name') != ResidentObj.name:
				return 'N','100','PI_NOT_MATCH_NAME_EXACT' # Pi attributes did not match
			if match_l:
				if PiNode.get('lname') != ResidentObj.lname:
					return 'N','100','PI_NOT_MATCH_LNAME_EXACT' # Pi attributes did not match
		if PiNode.get('gender') != ResidentObj.gender:
			return 'N','100','PI_NOT_MATCH_GENDER'

		# Check if dob is age or dob
		if '-' in PiNode.get('dob'):
			# Check if format is correct
			DOBparts = PiNode.get('dob').split('-')
			if not( len(DOBparts[0])==4 and len(DOBparts[1])==2 and len(DOBparts[2]) == 2):
				return 'N','902','PI_BAD_DOB' # Invalid DOB value
			if PiNode.get('dob') != ResidentObj.dob:
				return 'N','100','PI_NOT_MATCH_DOB'
		else:
			try:
				if not (int(PiNode.get('age')) == (datetime.now().year - int(ResidentObj.dob.split('-')[0]))):
					return 'N','100','PI_NOT_MATCH_AGE'
				if (datetime.now().year - int(ResidentObj.dob.split('-')[0])) > 150:
					return 'N','902','PI_BAD_DOB' # age beyond acceptable limit
			except:
				return 'N','999','PI_AGE_DECODE_ERR'

		# Match phone and email
		if not (PiNode.get('phone') == ResidentObj.phone):
			return 'N','100','PI_NOT_MATCH_PHONE'

		if not (PiNode.get('email') == ResidentObj.email):
			return 'N','100','PI_NOT_MATCH_MAIL'

	PaNode = PIDNode.find('Demo').find('Pa')
	if lambdayn(UsesNode.get('pa')):
		if (not lambda10(Rights[1])):
			return 'N','574','NOT_ALLOWED_TO_PA' # Not allowed to PA
		if PaNode is None:
			return 'N','720','NO_VALUES_FOR_PA' # Not given PA
		if PaNode.get('ms') != 'E':
			return 'N','200','BAD_VALUE_PA_MS' # Pa did not match
		if PaNode.get('co') != ResidentObj.care_of:
			return 'N','200','NOT_MATCH_PA_CO'
		if PaNode.get('house') != ResidentObj.address['house']:
			return 'N','200','NOT_MATCH_PA_HOUSE'
		if PaNode.get('street') != ResidentObj.address['street']:
			return 'N','200','NOT_MATCH_PA_STREET'
		if PaNode.get('lm') != ResidentObj.address['lm']:
			return 'N','200','NOT_MATCH_PA_LM'
		if PaNode.get('vtc') != ResidentObj.address['vtc']:
			return 'N','200','NOT_MATCH_PA_VTC'
		if PaNode.get('subdist') != ResidentObj.address['subdist']:
			return 'N','200','NOT_MATCH_PA_SUBDIST'
		if PaNode.get('dist') != ResidentObj.address['dist']:
			return 'N','200','NOT_MATCH_PA_DIST'
		if PaNode.get('state') != ResidentObj.address['state']:
			return 'N','200','NOT_MATCH_PA_STATE'
		if PaNode.get('pc') != ResidentObj.address['pc']:
			return 'N','200','NOT_MATCH_PA_PC'
		if PaNode.get('po') != ResidentObj.address['po']:
			return 'N','200','NOT_MATCH_PA_PO'
		if PaNode.get('lco') != ResidentObj.lcare_of:
			return 'N','200','NOT_MATCH_PA_LCO'

	PfaNode = PIDNode.find('Demo').find('Pfa')
	if lambdayn(UsesNode.get('pfa')):
		if (not lambda10(Rights[2])):
			return 'N','575','NOT_ALLOWED_TO_PFA' # Not allowed to PFA
		if PfaNode is None:
			return 'N','721','NO_VALUES_FOR_PFA' # Not given PFA
		if PfaNode.get('ms') == 'P':
			if not lambda10(Rights[8]):
				return 'N','581','NOT_ALLOWED_FUZZY_MATCHING_PFA' # Fuzzy matching not allowed
			# create AV
		mv_val =100 if PfaNode.get('mv')== "" else PfaNode.get('mv')
		if not fuzzyStr(mv_val,PfaNode.get('av'),' '.join(ResidentObj.address.values())):
			return 'N','200','PFA_NOT_MATCH_FUZZY_AV'

		lmv_val = 100 if PfaNode.get('lmv')=="" else PfaNode.get('lmv')
		if not fuzzyStr(PfaNode.get('mv'),PfaNode.get('lav'),' '.join(ResidentObj.laddress.values())):
			return 'N','200','PFA_NOT_MATCH_FUZZY_LAV'

	if lambdayn(UsesNode.get('bio')):
		bt_attr = UsesNode.get('bt')
		if bt_attr =="":
			return 'N','820','BT_EMPTY' # Empty value of bt even though bio == True
		else:
			allowed_bio_list = []
			if lambda10(Rights[3]):
				allowed_bio_list.append('FMR')
			if lambda10(Rights[4]):
				allowed_bio_list.append('FIR')
			if lambda10(Rights[5]):
				allowed_bio_list.append('IIR')

			# Check if bt attribute has unexpected values
			if not all(i in ['FMR','FIR','IIR'] for i in bt_attr.split(',')):
				return 'N','821','BT_INVALID' # Invalid value for bt

			# Check if bt attribute asked but not allowed
			for i in bt_attr.split(','):
				if i not in allowed_bio_list:
					if i == 'FMR':
						return 'N','576','FMR_NOT_ALLOWED' # FMR asked but not allowed
					if i == 'FIR':
						return 'N','577','FIR_NOT_ALLOWED' # FIR asked but not allowed
					if i == 'IIR':
						return 'N','578','IIR_NOT_ALLOWED' # IIR asked but not allowed

			# Get all bios information for resident

			for i in PIDNode.find('Bios').findall('Bio'):
				if i.get('type') not in ['FMR','FIR','IIR']:
					return 'N','824','NA' # invalid value for Bio
				elif i.get('type') not in allowed_bio_list:
					if i.get('type') == 'FMR':
						return 'N','1576','1FMR_NOT_ALLOWED' # FMR asked but not allowed
					if i.get('type') == 'FIR':
						return 'N','1577','1FIR_NOT_ALLOWED' # FIR asked but not allowed
					if i.get('type') == 'IIR':
						return 'N','1578','1IIR_NOT_ALLOWED' # IIR asked but not allowed
				else:
					# Check if position values are ok.
					if i.get('posh') not in valid_dict[i.get('type')]:
						return 'N','572','INVALID_POSH' # Invalid Biometric position
					# Check if all existing values match with the saved ones
					try:
						if i.get('posh') == 'UNKNOWN':
							if not (i.text in ResidentObj.bios[i.get('type')].values()):
								return 'N','300','BIOMETRIC_MISMATCH' # Biometric data not matched
						elif not (i.text == ResidentObj.bios[i.get('type')][i.get('posh')]):
							return 'N','300','BIOMETRIC_MISMATCH' # Biometric data not matched
					except:
						return 'N','811','BIOMETRIC_NOT_AVAILABLE' # Biometric Value not Available

	return 'PASS','PASS','PASS'

def getResponseXML(AuthNodeData, ver, ac, asa,is_kyc=False):
	try:
		AuthNode = etree.fromstring(AuthNodeData)
	except:
		ret = 'N'
		err = '999' # Could not parse to XML
		code = 'BAD_XML_AUTH_NODE'
		return prepareResponseNode(None,ret,err,code)

	if not is_kyc:
		if not (AuthNode.get('ver') == '1.6' == ver):
			ret = 'N'
			err = '540' # Invalid Auth XML version
			code = 'INVALID_AUTH_XML_VERSION'
			return prepareResponseNode(AuthNode,ret,err,code)
	else:
		if not (AuthNode.get('ver') == '1.6'):
			ret = 'N'
			err = '540' # Invalid Auth XML version
			code = 'INVALID_AUTH_XML_VERSION'
			return prepareResponseNode(AuthNode,ret,err,code)
	# If Authnode ac matches as of URL
	if AuthNode.get('ac') != ac:
		return prepareResponseNode(AuthNode,'N','999','MISMATCH_AC')
	# If asa matches sa
	if AuthNode.get('sa') != asa:
		return prepareResponseNode(AuthNode,'N','999','MISMATCH_SA')
	# Check if aadhaar number exists
	try:
		ResidentObj = Resident.objects.get(uid__exact = AuthNode.get('uid'))
	except:
		ret = 'N'
		err = '998' # invalid aadhaar number
		code = 'INVALID_UID'
		return prepareResponseNode(AuthNode,ret,err,code)

	if not isSignatureValid(AuthNode.find('Signature').text):
		ret = 'N'
		err = '569' # Invalid signature
		code = 'INVALID_SIGNATURE'
		return prepareResponseNode(AuthNode,ret,err,code)

	# Check if the request Skey's Ci has invalid ci
	if not isCIValid(AuthNode):
		ret = 'N'
		err = '501' # Invalid CI of Skey
		code = 'INVALID_CI_SKEY'
		return prepareResponseNode(AuthNode,ret,err,code)

	if not isLicenseValid(AuthNode):
		ret = 'N'
		err = '502'
		code = 'INVALID_EXPIRED_LICENSE'
		return prepareResponseNode(AuthNode,ret,err,code)

	# If ci is valid then decrypt the skey
	try:
		skey = decryptSkey(AuthNode)
	except:
		ret = 'N'
		err = '500' # Invalid encryption of Skey
		code = "INVALID_ENCRYPTION_SKEY"
		return prepareResponseNode(AuthNode,ret,err,code)

	# decode PID
	try:
		PIDText = AuthNode.find('Data').text
		PID = decryptWithSession(skey, PIDText)
	except:
		ret = 'N'
		err = '502' # invalid encryption of PID
		code = 'INVALID_ENCRYPTION_PID'
		actn = 'RETRY'
		return prepareResponseNode(AuthNode,ret,err,code,actn)

	try:
		if AuthNode.find('Data').get('type') == 'X':
			PID = PID.split(b'</Pid>')[0]+b'</Pid>'
			PIDNode = etree.fromstring(PID)
			if PIDNode.get('ver') != '1.0':
				ret = 'N'
				err = '541' # invalid version of PID
				code = 'INVALID_VERSION_PID'
				return prepareResponseNode(AuthNode,ret,err,code)
		else:
			ret = 'N'
			err = '511' # invalid PID format
			code = 'INVALID_PID_FORMAT'
			return prepareResponseNode(AuthNode,ret,err,code)
	except:
		ret = 'N'
		err = '511' # invalid PID format
		code = 'INVALID_PID_FORMAT'
		return prepareResponseNode(AuthNode,ret,err,code)
	# Calculate Hmac and match
	try:
		Hmac = decryptWithSession(skey, AuthNode.find('Hmac').text)
	except:
		ret = 'N'
		err = '503' # invalid encryption of Hmac
		code = 'INVALID_ENCRYPTION_HMAC'
		return prepareResponseNode(AuthNode,ret,err,code)

	if sha256(PID).digest() != Hmac.strip():
		ret = 'N'
		err = '564' # hmac validation failed
		code = 'HMAC_MISMATCH'
		actn = "RETRY"
		return prepareResponseNode(AuthNode,ret,err,code,actn)

	Rights = getLicenseRights(AuthNode)
	ret,err,code = isUsesPidValid(AuthNode.find('Uses'), PIDNode,Rights , ResidentObj)
	# Check anomalies related to PID if no anomalies exists then ret == err == code == 'PASS'
	if ret == err== code == 'PASS':
		pass
	else:
		return prepareResponseNode(AuthNode,ret,err,code)
	# Does it require OTP Authentication as well ?
	if AuthNode.find('Uses').get('otp')=='Y':
		# Does it have permission for OTP
		if Rights[6]=='0':
			return 'N','579','OTP_USAGE_NOT_ALLOWED'
		# Connect with the cacheDB (redis @ 2) and fetch the latest OTP corresponding to hash of UID
		s = StrictRedis(host='localhost',port=6379,db=2)
		uid_hash = sha256(bytes(AuthNode.get('uid'),'utf-8')).hexdigest()
		if s.get(uid_hash) is None:
			return prepareResponseNode(AuthNode,'N','401','NO_OTP_GENERATED')
		if s.get(uid_hash).decode('utf-8') != PIDNode.find('Pv').get('otp'):
			return prepareResponseNode(AuthNode,'N','400','INVALID_OTP_VALUE')

	return prepareResponseNode(AuthNode,'Y','','OK')

def prepareResponseNode(AuthNode,ret,err,code,actn=""):
	ts = currentISO8601()
	if AuthNode is not None:
		info = getInfo(AuthNode)
		txn = AuthNode.get('txn')
	else:
		info = ""
		txn = ""

	AuthResNode = createNode('AuthRes',['ret','code','txn','err','ts','actn','info'],[ret, code, txn, err, ts, actn, info])
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

	TransformsNode.append(TransformNode)

	ReferenceNode.append(TransformsNode)
	ReferenceNode.append(DigestMethodNode)
	ReferenceNode.append(DigestValueNode)

	SignedInfoNode.append(CanonicalizationMethodNode)
	SignedInfoNode.append(SignatureMethodNode)
	SignedInfoNode.append(ReferenceNode)

	SignatureNode.append(SignatureValueNode)
	SignatureNode.append(SignedInfoNode)

	AuthResNode.append(SignatureNode)

	return etree.tostring(AuthResNode)

def prepareResponseInit(AuthNodeData, ver, ac, asalk):
	if asalk == "":
		return prepareResponseNode(None,'N','942','UNSPECIFIED_ASA_CHANNEL')
	try:
		asa = ASA.objects.get(asalk__exact=asalk)
		if ac not in asa.Data['AUAList']:
			return prepareResponseNode(None,'N','542','AUA_NOT_AUTHORIZED_BY_ASA')
	except:
		return prepareResponseNode(None,'N','942','UNSPECIFIED_ASA_CHANNEL')
	try:
		AUA.objects.get(auaID__exact = ac)
	except:
		return prepareResponseNode(None,'N','543','AUA_DOES_NOT_EXIST')
	# Check if version
	return getResponseXML(AuthNodeData,ver,ac,asa.asaID)
