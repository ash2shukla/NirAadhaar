from sys import path as sys_path
from os import path
from json import load

NirAadhaarURL = "http://localhost:8000/" 			# NirAadhaar's port

PublicKeyPath = path.abspath(path.join(__file__,'..',"TEST_CENTER.public.pem")) 							# Public Key provided by NirAadhaar
CertPath = path.abspath(path.join(__file__,'..',"TEST_CENTER-AUA_CERT/TEST_CENTER-AUA-USER.cert.pem")) 		# Digital Certificate Path
DBPath = path.abspath(path.join(__file__,'..','lkd.db')) 													# LicenseKey Database Path (Should not be changed unless you're sure what you are doing)
DemoData = load(open(path.abspath(path.join(__file__,'..','Input.json')))) 									# A Demo input of registered user's values
InputTemplate = load(open(path.abspath(path.join(__file__,'..','Input_Template.json')))) 					# An Input template. Shove in values in this template.

ver = "1.6" 			# Version of API , only acceptable value is 1.6
ac = "TEST_AUA" 		# AC = AUA
sa = "TEST_ASA" 		# SA = ASA , for now Sub ASA not supported
aua = "TEST_AUA" 		# HealthCenter / AUA's name goes here
asalk = "TEST_ASALK"	# We want to use ASA as AUA
is_Fingerprint = False 	# Set to False if not using Fingerprint Identification
is_Iris = False 		# Set to False if not using Iris Identification
lot = "G" 				# can also set it to P
ki = ""					# OtherDocuments/DigitalCertificates_ for other info
dtype="X"				# For now only XML is supported, Acceptable value is "P" as well in Aadhaar but not implemented yet.
is_otp =True 			# Set True if you want to verify using OTP as well
is_pin = False 			# DO NOT SET TRUE, PIN HAS NO MEANINGS, ITS FOR INTERNAL PURPOSES OF CIDR ONLY
is_asa_cert= False 		# DO NOT SET TRUE, ASA WONT SIGN INSTEAD OF AUA
tkntype= "" 			# Token usage is ambiguous and not documented thus not implemented in NirAadhaar for now.
tknvalue = "" 			# Same applies for Token Value

############################# VARIABLES FOR EKYC ##############################

ekyc_ver = "2.0" 		# Version of eKYC, only acceptable value is 2.0
ra = "O" 				# F,I,O,P Fingerprint, Iris, OTP and Pin
						# IT MUST MATCH WITH PID Uses block
rc = "Y" 				# resident's consent can only be Y
mec = "Y" 				# get mobile and email's consent
lr = "N" 				# Get Local Reigional Language Data
de = "Y" 				# Y = KUA/AUA encrypts N = KSA/ASA encrypts
pfr = "N" 				# Print format Request (Returns a PDF as well)
