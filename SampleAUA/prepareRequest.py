from sys import version_info
from sys import path as sys_path
from json import load
from os import path
from lxml import etree
from hashlib import sha256
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .Utils import *
from .getInformation import *
from .config import *


# create the Skey and save it for session
skey,EncryptedSkey = getSkey()

isNone = lambda lst : 'N' if all([i=="" for i in lst]) else 'Y'

def createTknNode():
	elements = ['type','value']
	values = [tkntype,tknvalue]

	node = createNode('Tkn',elements,values)

	return node

def createMetaNode():
	elements = ['udc','fdc','idc','pip','lot','lov']
	values = [getUDC(),getFDC(is_Fingerprint),getIDC(is_Iris),getPIP(),lot,getLOV(lot)]

	node = createNode('Meta',elements, values)

	return node

def createPiNode(JSONInput):
	if JSONInput['name'] != "":
		ims = "E" # ms for Pi (Identity)
		imv = "" # Pecentage match if partial ms for Pi
	else:
		ims = ""
		imv = ""

	if JSONInput['lname'] != "":
		ilmv = "90" # Percentage match if name lname of person given in Pi
	else:
		ilmv = ""

	elements = ['ms','mv','lmv']
	values = [ims,imv,ilmv]

	elements_from_json = ['name','lname','gender','dob','dobt','age','phone','email']

	[ (elements.append(i),values.append(JSONInput[i])) for i in elements_from_json ]

	node = createNode('Pi',elements,values)

	return node

def createPaNode(JSONInput):
	elements = []
	values = []

	elements_from_json = ['co','house','street','lm','lco','vtc','subdist','dist','state','pc','po']

	if isNone([ (elements.append(i),values.append(JSONInput[i])) for i in elements_from_json ]) == 'Y':
		elements.append('ms')
		values.append('E')

	node = createNode('Pa',elements,values)

	return node

def createPfaNode(JSONInput):
	if JSONInput['av'] is not "":
		fams = "P" # ms for Pfa (Full Address)
		famv = "60" # mv for Pfa
	else:
		fams = ""
		famv = ""

	if JSONInput['lav'] != "":
		falmv="60" # mv for Pfa in language
	else:
		falmv = ""

	elements = ['ms','mv','lmv']
	values = [fams,famv,falmv]

	elements_from_json = ['av','lav']

	[ (elements.append(i),values.append(JSONInput[i])) for i in elements_from_json ]

	node = createNode('Pfa',elements,values)

	return node

def createPvNode(otp):
	elements = ['otp','pin']
	values = [otp,getPIN(is_pin)]

	node = createNode('Pv',elements,values)

	return node

def createDemoNode(Pi,Pa,Pfa,lang):
	DemoNode = createNode('Demo',['lang'],[lang])
	DemoNode.append(Pi)
	DemoNode.append(Pa)
	DemoNode.append(Pfa)

	return DemoNode

def createPIDNode(DemoNode, BiosNode, PvNode):
	elements = ['ts','ver']
	values = [currentISO8601(), '1.0']

	PIDNode = createNode('Pid',elements,values)
	PIDNode.append(DemoNode)
	PIDNode.append(BiosNode)
	PIDNode.append(PvNode)

	return PIDNode

def createDataNode(PIDNode):
	elements = ['type']
	values = [dtype]
	text = encryptWithSession(skey, etree.tostring(PIDNode))

	return createNode('Data',elements, values,text)

def createHmacNode(PIDNode):
	digest = sha256(etree.tostring(PIDNode)).digest()
	text = encryptWithSession(skey,digest)

	return createNode('Hmac',[],[],text)

def createUsesNode(Pi,Pa,Pfa,bio_dict):
	usesBio = 'N' if bio_dict == {} else 'Y'
	bt = ','.join(bio_dict.keys())
	usesPin = 'Y' if is_pin else 'N'
	usesOtp = 'Y' if is_otp else 'N'

	elements = ['pi','pa','pfa','bio','bt','pin','otp']
	values = [isNone(Pi.values()), isNone(Pa.values()), isNone(Pfa.values()), usesBio, bt, usesPin, usesOtp]

	node = createNode('Uses', elements, values)

	return node

def createSignatureNode():
	if not is_asa_cert:
		return createNode('Signature',[],[],getCertificate('raw'))
	else:
		return createNode('Signature',[],[])

def createBiosNode(bio_dict):
	BiosNode = createNode('Bios',[],[])

	for i,lst in zip(bio_dict.keys(),bio_dict.values()):
		for j,k in zip(lst.keys(),lst.values()):
			BiosNode.append(createNode('Bio',["type","posh"],[i,j],k))

	return BiosNode

def createSkeyNode():
		return createNode('Skey',['ci'],[getCertificate('expiry')], EncryptedSkey)

def createAuthNode(JSONInput,NodeList,for_KYC):
	uid = JSONInput['uid']

	elements = ['uid','tid','ac','sa','ver','txn','lk']

	# Transaction ID must start with UKC: namespace for_KYC transactions
	txn = "UKC:"+getTxnID(aua,uid) if for_KYC else getTxnID(aua,uid)

	values = [uid,getTID(),aua,sa,ver,txn,getLicenseKey(aua)]

	AuthNode = createNode('AuthNode',elements,values)

	[AuthNode.append(i) for i in NodeList]

	return AuthNode

def populateAuthXML(JSONInput,otp="",for_KYC=False):
	# JSONInput must be in the same form as mentioned in Input.json
	# If some fields do not exist then simply put "" instead of value

	# if is_otp == true then value of otp must be input by user

	TknNode = createTknNode()
	MetaNode = createMetaNode()
	PiNode = createPiNode(JSONInput)
	PaNode = createPaNode(JSONInput)
	PfaNode = createPfaNode(JSONInput)
	PvNode = createPvNode(otp)
	DemoNode = createDemoNode(PiNode,PaNode,PfaNode,JSONInput['lang'])
	BiosNode = createBiosNode(JSONInput['bio_dict'])
	PIDNode = createPIDNode(DemoNode, BiosNode, PvNode)
	DataNode = createDataNode(PIDNode)
	UsesNode = createUsesNode(PiNode,PaNode,PfaNode,JSONInput['bio_dict'])
	SignatureNode = createSignatureNode()

	HmacNode = createHmacNode(PIDNode)
	SkeyNode = createSkeyNode()

	AuthNode = createAuthNode(JSONInput,[UsesNode,TknNode,MetaNode,SkeyNode,DataNode,HmacNode,SignatureNode],for_KYC)
	return etree.tostring(AuthNode)

def AuthRes(AuthXML):
	'''
	Invokes Auth Request.
	'''
	AuthNode = etree.fromstring(AuthXML)
	uid = AuthNode.get("uid")
	r = Request(NirAadhaarURL+ver+"/"+ac+"/"+uid[0]+"/"+uid[1]+"/"+asalk+"/", data=AuthXML)
	response = loads(urlopen(r).read())

	return response

#################################### For OTP ###################################

def populateOTPXML(ch,uid):
	OtpNode = createNode('Otp',['uid','tid','ac','sa','ver','txn','lk','type'],[uid,getTID(),ac,sa,ver,getTxnID(ac,uid),getLicenseKey(ac),'A'])
	OptsNode = createNode('Opts',['ch'],[ch])
	SignatureNode = createNode('Signature',[],[],getCertificate('raw'))
	OtpNode.append(OptsNode)
	OtpNode.append(SignatureNode)

	return etree.tostring(OtpNode)

def OTPRes(uid,OTPXML):
	'''
	Invokes OTP request.
	'''
	r = Request(NirAadhaarURL+'otp'+'/'+ver+'/'+ac+'/'+uid[0]+'/'+uid[1]+'/'+asalk+'/', data=OTPXML)
	response = loads(urlopen(r).read())
	return response

#################################### For eKYC ##################################

def populateKYCXML(AuthXMLData):
	elements = ['ver','ts','ra','rc','mec','lr','de','pfr']
	values = [ekyc_ver,currentISO8601(), ra,rc,mec,lr,de,pfr]
	return etree.tostring(createNode('Kyc', elements, values,AuthXMLData))

def KycRes(KYCXML,uid):
	'''
	Invokes eKYC request.
	'''
	r = Request(NirAadhaarURL+'kyc'+'/'+ver+'/'+ac+'/'+uid[0]+'/'+uid[1]+'/'+asalk+'/', data=KYCXML)
	response = loads(urlopen(r).read())
	return response
