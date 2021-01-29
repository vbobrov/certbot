import json
from cryptography import x509
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates,load_key_and_certificates
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from webexteamssdk import WebexTeamsAPI
from cards import *
import binascii
import re
import requests
import os
import json
import hmac
import ipaddress

def validIp(ip):
	try:
		ipaddress.ip_address(ip)
	except ValueError:
		return(False)
	return(True)

def validEmail(email):
    return(re.search(r'^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$',email))

def validDns(hostName):
    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostName.split("."))

def getMsgOption(msgText,optionName):
	if msgText:
		optionRegEx=re.findall(rf'.*{optionName}:(\S+).*',msgText,re.IGNORECASE|re.MULTILINE)
		if optionRegEx:
			return(optionRegEx[0])
		else:
			return(None)
	else:
		return(None)

def csrInfo(csr):
	result="CSR Information:\n"
	result+=f'Subject: {csr.subject.rfc4514_string()}\n'
	result+=f'Key Size: {csr.public_key().key_size}\n'
	for ext in csr.extensions:
		if ext.oid==x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
			result+='Subject Alt Names:\n'
			for altname in ext.value:
				result+=f'  {altname.value}\n'
		if ext.oid==x509.oid.ExtensionOID.KEY_USAGE:
			result+='Key Usage:\n'
			for keyusage,enabled in ext.value.__dict__.items():
				if enabled:
					result+=f'  {keyusage}\n'
		if ext.oid==x509.oid.ExtensionOID.EXTENDED_KEY_USAGE:
			result+='Extended Key Usage:\n'
			for eku in ext.value:
				result+=f'  {eku._name}\n'
	return(result)

def x509info(x509cert,showPem=False):
	result="Certificate Information:\n"
	result+=f'Serial Number: {x509cert.serial_number}\n'
	result+=f'Issuer: {x509cert.issuer.rfc4514_string()}\n'
	result+=f'Subject: {x509cert.subject.rfc4514_string()}\n'
	result+=f'Valid from {x509cert.not_valid_before} to {x509cert.not_valid_after}\n'
	result+=f'Key Size: {x509cert.public_key().key_size}\n'
	for ext in x509cert.extensions:
		if ext.oid==x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
			result+='Subject Alt Names:\n'
			for altname in ext.value:
				result+=f'  {altname.value}\n'
		if ext.oid==x509.oid.ExtensionOID.KEY_USAGE:
			result+='Key Usage:\n'
			for keyusage,enabled in ext.value.__dict__.items():
				if enabled:
					result+=f'  {keyusage}\n'
		if ext.oid==x509.oid.ExtensionOID.EXTENDED_KEY_USAGE:
			result+='Extended Key Usage:\n'
			for eku in ext.value:
				result+=f'  {eku._name}\n'
		#print(f"{ext.oid} {ext.value}")
	if showPem:
		result+=x509cert.public_bytes(serialization.Encoding.PEM).decode()
	return(result)

def rsaInfo(rsaKey,password=None,showPem=False):
	result="Private Key Information:\n"
	result+=f'Key Size {rsaKey.key_size}\n'
	if showPem:
		result+=rsaKey.private_bytes(serialization.Encoding.PEM,format=serialization.PrivateFormat.TraditionalOpenSSL,encryption_algorithm=serialization.BestAvailableEncryption(password)).decode()+"\n"
	return(result)

def parseWbxMsg(wbxMsg,certBotKey):
	global keyPassword,pfxPassword
	errors=""
	msgFiles={}
	if wbxMsg.files:
		for fileUrl in wbxMsg.files:
			response=requests.get(fileUrl,headers={'Authorization': f'Bearer {certBotKey}'})
			fileContent=response._content
			try:
				msgFiles['cert']=x509.load_pem_x509_certificate(fileContent)
			except Exception as e:
				pass
			try:
				msgFiles['cert']=x509.load_der_x509_certificate(fileContent)
			except Exception as e:
				pass
			try:
				msgFiles['key']=serialization.load_pem_private_key(fileContent,password=keyPassword)
			except Exception as e:
				if re.match(r'.*password.*',str(e),flags=re.IGNORECASE):
					errors+=f'Private Key Error: {e}. Specify password with keypassword:<password>.\n'
			try:
				msgFiles['csr']=x509.load_pem_x509_csr(fileContent)
			except:
				pass
			try:
				msgFiles['pkcs12']=load_key_and_certificates(fileContent,str(pfxPassword).encode())
			except Exception as e:
				if re.match(r'.*password.*',str(e),flags=re.IGNORECASE):
					errors+=f'PFX Error: {e}. Specify password with pfxpassword:<password>.\n'
	try:
		msgFiles['cert']=x509.load_pem_x509_certificate(wbxMsg.text.encode())
	except Exception as e:
		pass
	try:
		msgFiles['cert']=x509.load_der_x509_certificate(binascii.a2b_hex(re.sub(r'[^0-9a-fA-F]','',wbxMsg.text)))
	except Exception as e:
		pass
	try:
		msgFiles['key']=serialization.load_pem_private_key(wbxMsg.text.encode(),password=keyPassword)
	except Exception as e:
		if re.match(r'.*password.*',str(e),flags=re.IGNORECASE):
			errors+=f'Private Key Error: {e}. Specify password with keypassword:<password>.\n'
	try:
		msgFiles['csr']=x509.load_pem_x509_csr(wbxMsg.text.encode())
	except:
		pass
	return(errors,msgFiles)

def lambda_handler(event, context):
	help="""# Welcome to Cert Bot
## Introduction
Cert Bot provide several crypto utilities with a simple chat interfaces
It accepts the information via attachments as well as text pasted directly as a message.
**Cert Bot will never output a private key unless it's encrypted with the password you provide. After the information you requested is provided by Cert Bot, be sure to delete your original message with any sensitive information.**
## Certificate Parsing
Cert Bot will parse the several crypto formats and output information in human readable form.
The following formats are supported:
 - PEM or DER encoded certificates
 - Hexadecimal certificate blobs pasted from ASA or IOS ***crypto ca certificate chain*** commands. Only paste the hexadecimal portion, white spaces do not need to be removed.
 - PEM encoded Certificate Signing Requests (CSR/PKCS10) 
 - PEM encoded private keys, encrypted and unencrypted. If the private key is encrypted, password must be specified in the same Teams message in the following format: keypassword:***password***.
 - PKCS12 files. Since these files are binary, they can only be accepted as attachments. Password must be in the same message in the following format: pfxpassword:***password***. Cert Bot will only print out the private key if an encryption password is specified with keypassword:***password***.
## CSR Generation
Cert Bot simplifies creation of a CSR with input provided by the user.
CSR can be generated using an existing private key or a new private key can be computed by Cert Bot
To initiate CSR process, the command is cmd:csr.
To use an existing key, simply attach or paste it to the same Teams message. If the existing key is encrypted be sure to specify the key password as described above.
If a key is not provided, a new key will be generated. Key password must be specified, Cert Bot will not output an unencrypted private key
Cert Bot will respond with an interactive form for CSR parameters. The form includes the following information:
 - Common Name (CN)
 - E-Mail Address (E)
 - Organizational Unit (OU). Multiple OU's can be specified, comma-separated
 - Domain Component (DC). Multiple DC's can be specified, comma-separated
 - Organization (O)
 - Locality/City (L)
 - State (ST)
 - Country (C)
 - Subject Alternative Names (SAN). Multiple SAN values can be specified, comma-separated. The following SAN types are supported:
	 - DNS Name
	 - IP Address
	 - E-mail Address. This will be saved as User Principal Name (UPN)
- Key Size for a new key. Supported Values are 2048 and 4096. If an existing private key is used, this field is disabled.
- Key Usage. Server Authentication and Client Authentication are supported
## PKCS12 (PFX) Generation
Cert Bot can generate pkcs12 files given a certificate and a private key. To do this, the following information must be in the same message
- Keyword to trigger pfx encoding: ***cmd:pfx***
- Certificate, pasted or attached
- Private key, pasted or attached. If key is encrypted, password must be specified as explained above.
- Password for the output PKCS12 file: pfxpassword:***password***

For example, to generate a PKCS12 file based on an encrypted private key, you would add the following text to the message ***cmd:pfx keypassword:mysecretkey pfxpassword:mybundlekey***
	"""
	global keyPassword,pfxPassword,csrCardJson
	if os.getenv('FLASK_APP') or os.getenv('AWS_SAM_LOCAL'):
		certBotKey=os.getenv('WEBEX_TEAMS_DEV_TOKEN')
		botEmail='vbdev@webex.bot'
	else:
		certBotKey=os.getenv('WEBEX_TEAMS_ACCESS_TOKEN')
		botEmail='certbot@webex.bot'
	webHookKey=os.getenv('WEBEX_HOOK_KEY')
	print(json.dumps(event))
	if not os.getenv('FLASK_APP'):
		sparkSignature=event['headers']['X-Spark-Signature']
		msgDigest=binascii.b2a_hex(hmac.digest(webHookKey.encode(),event['body'].encode(),'sha1'))
		if  msgDigest!=sparkSignature.encode():
			return {
				"statusCode": 403,
				"body": "{}"
			}
	webhookData=json.loads(event['body'])
	wbxApi=WebexTeamsAPI(access_token=certBotKey)
	pfxPassword=None
	keyPassword=None
	if webhookData['resource']=='messages':
		if not 'parentId' in webhookData['data'] and webhookData['data']['personEmail']!=botEmail:
			wbxMsg=wbxApi.messages.get(webhookData['data']['id'])
			cmd=getMsgOption(wbxMsg.text,'cmd')
			keyPassword=getMsgOption(wbxMsg.text,'keypassword')
			if keyPassword:
				keyPassword=keyPassword.encode()
			pfxPassword=getMsgOption(wbxMsg.text,'pfxpassword')
			(errors,msgFiles)=parseWbxMsg(wbxMsg,certBotKey)
			displayHelp=True
			if 'cert' in msgFiles:
				wbxApi.messages.create(toPersonEmail=wbxMsg.personEmail,parentId=wbxMsg.id,text=x509info(msgFiles['cert']))
				displayHelp=False
			if 'key' in msgFiles:
				wbxApi.messages.create(toPersonEmail=wbxMsg.personEmail,parentId=wbxMsg.id,text=rsaInfo(msgFiles['key']))
				displayHelp=False
			if 'csr' in msgFiles:
				wbxApi.messages.create(toPersonEmail=wbxMsg.personEmail,parentId=wbxMsg.id,text=csrInfo(msgFiles['csr']))
				displayHelp=False
			if 'pkcs12' in msgFiles:
				if keyPassword:
					pemKey=msgFiles['pkcs12'][0].private_bytes(serialization.Encoding.PEM,format=serialization.PrivateFormat.TraditionalOpenSSL,encryption_algorithm=serialization.BestAvailableEncryption(keyPassword))
					response = requests.post("https://webexapis.com/v1/messages",
											headers={'Authorization': f'Bearer {certBotKey}'},
											data={'toPersonEmail': wbxMsg.personEmail,'parentId':wbxMsg.id,'text': 'Encrypted Private Key'},
											files = {'files': ('privatekey.txt',pemKey,'application/pkcs8')})
				else:
					errors+="To output private key, specify keypassword"
				pemCert=msgFiles['pkcs12'][1].public_bytes(serialization.Encoding.PEM)
				response = requests.post("https://webexapis.com/v1/messages",
											headers={'Authorization': f'Bearer {certBotKey}'},
											data={'toPersonEmail': wbxMsg.personEmail,'parentId':wbxMsg.id,'text': x509info(msgFiles['pkcs12'][1],False)},
											files = {'files': ('certificate.txt',pemCert,'application/pkix-cert')})
				displayHelp=False
			if cmd=='pfx':
				if 'cert' in msgFiles and 'key' in msgFiles and pfxPassword:
					pfx=serialize_key_and_certificates(b"PFX",msgFiles['key'],msgFiles['cert'],None,serialization.BestAvailableEncryption(pfxPassword.encode()))
					response = requests.post("https://webexapis.com/v1/messages",
											headers={'Authorization': f'Bearer {certBotKey}'},
											data={'toPersonEmail': wbxMsg.personEmail,'parentId':wbxMsg.id,'text': 'PFX File Generated'},
											files = {'files': ('bundle.p12',pfx,'application/x-pkcs12')})
				else:
					errors+='PFX command requires certificate, key and pfx password.\n'
				displayHelp=False
			if cmd=='csr':
				displayHelp=False
				csrCard=json.loads(csrCardJson)
				displayCard=False
				if 'key' in msgFiles:
					csrCard['body'][10]['columns'][1]['items']=[{'type': 'TextBlock', 'text': str(msgFiles['key'].key_size), 'id': ''}]
					displayCard=True
				elif not keyPassword:
					errors+="Key Password is required when generating a new key\n"
				else:
					displayCard=True
				if displayCard:
					cardAttachment={"contentType":"application/vnd.microsoft.card.adaptive","content":csrCard}
					wbxApi.messages.create(toPersonEmail=wbxMsg.personEmail,parentId=wbxMsg.id,text='Please provide CSR details',attachments=[cardAttachment])
			if errors:
				wbxApi.messages.create(toPersonEmail=wbxMsg.personEmail,parentId=wbxMsg.id,text=errors)
				displayHelp=False
			if displayHelp:
				wbxApi.messages.create(toPersonEmail=wbxMsg.personEmail,parentId=wbxMsg.id,markdown=help)
	if webhookData['resource']=='attachmentActions':
		wbxAction=wbxApi.attachment_actions.get(webhookData['data']['id'])
		wbxMsg=wbxApi.messages.get(webhookData['data']['messageId'])
		try:
			try:
				replyError=True
				wbxMsg=wbxApi.messages.get(wbxMsg.parentId)
			except:
				replyError=False
				wbxApi.messages.delete(webhookData['data']['messageId'])
				raise Exception("Original message no longer available")
			keyPassword=getMsgOption(wbxMsg.text,'keypassword')
			msgFiles={}
			if keyPassword:
				keyPassword=keyPassword.encode()
			if not 'KeySize' in wbxAction.inputs:
				(errors,msgFiles)=parseWbxMsg(wbxMsg,certBotKey)
			else:
				msgFiles['key']=rsa.generate_private_key(public_exponent=65537,key_size=int(wbxAction.inputs['KeySize']),backend=default_backend())
			csr = x509.CertificateSigningRequestBuilder()
			dn=[]
			if wbxAction.inputs['C']:
				dn.append(x509.NameAttribute(x509.NameOID.COUNTRY_NAME, wbxAction.inputs['C']))
			if wbxAction.inputs['L']:
				dn.append(x509.NameAttribute(x509.NameOID.LOCALITY_NAME, wbxAction.inputs['L']))
			if wbxAction.inputs['DC']:
				for dc in reversed(wbxAction.inputs['DC'].split(',')):
					dn.append(x509.NameAttribute(x509.NameOID.DOMAIN_COMPONENT,dc.strip()))
			if wbxAction.inputs['O']:
				dn.append(x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, wbxAction.inputs['O']))
			if wbxAction.inputs['OU']:
				for ou in reversed(wbxAction.inputs['OU'].split(',')):
					dn.append(x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME,ou.strip()))
			if wbxAction.inputs['E']:
				dn.append(x509.NameAttribute(x509.NameOID.EMAIL_ADDRESS,wbxAction.inputs['E']))
			if wbxAction.inputs['CN']:
				dn.append(x509.NameAttribute(x509.NameOID.COMMON_NAME, wbxAction.inputs['CN']))
			csr = csr.subject_name(x509.Name(dn))
			if wbxAction.inputs['SAN']:
				x509sans=[]
				for san in wbxAction.inputs['SAN'].split(','):
					sanVal=san.strip()
					if validIp(sanVal):
						x509sans.append(x509.IPAddress(ipaddress.IPv4Address(sanVal)))
					elif validEmail(sanVal):
						x509sans.append(x509.OtherName(x509.oid.ObjectIdentifier('1.3.6.1.4.1.311.20.2.3'),b'\x0c'+bytes([len(sanVal)])+sanVal.encode()))
					else:
						x509sans.append(x509.DNSName(sanVal))
				csr=csr.add_extension(x509.SubjectAlternativeName(x509sans),critical=False)
			eku=[]
			if 'ServerAuth' in wbxAction.inputs['KeyUsage']:
				eku.append(x509.ExtendedKeyUsageOID.SERVER_AUTH)
			if 'ClientAuth' in wbxAction.inputs['KeyUsage']:
				eku.append(x509.ExtendedKeyUsageOID.CLIENT_AUTH)
			if eku:
				csr=csr.add_extension(x509.ExtendedKeyUsage(eku),critical=False)
			csr=csr.sign(msgFiles['key'], hashes.SHA256(), default_backend())
			pemKey=msgFiles['key'].private_bytes(serialization.Encoding.PEM,format=serialization.PrivateFormat.TraditionalOpenSSL,encryption_algorithm=serialization.BestAvailableEncryption(keyPassword))
			pemCsr=csr.public_bytes(serialization.Encoding.PEM)
			if 'KeySize' in wbxAction.inputs:
				response = requests.post("https://webexapis.com/v1/messages",
							headers={'Authorization': f'Bearer {certBotKey}'},
							data={'toPersonEmail': wbxMsg.personEmail,'parentId':wbxMsg.id,'markdown': 'New Private Key. ***Be sure to remove original message with password***'},
							files = {'files': ('newkey.txt',pemKey,'application/unknown')})
			response = requests.post("https://webexapis.com/v1/messages",
						headers={'Authorization': f'Bearer {certBotKey}'},
						data={'toPersonEmail': wbxMsg.personEmail,'parentId':wbxMsg.id,'markdown': 'CSR Request. ***Be sure to remove original message with password***'},
						files = {'files': ('request.txt',pemCsr,'application/unknown')})
			wbxApi.messages.delete(webhookData['data']['messageId'])
		except Exception as e:
			if replyError:
				wbxApi.messages.create(toPersonEmail=wbxMsg.personEmail,parentId=wbxMsg.id,text=f'Unable to generate CSR: {e}')
			else:
				wbxApi.messages.create(toPersonId=webhookData['data']['personId'],text=f'Unable to generate CSR: {e}')
	return {
		"statusCode": 200,
		"body": "{}"
	}
