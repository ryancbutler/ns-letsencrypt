#!/usr/bin/env python
#Automates the certificate renewal process for Netscaler via REST API and dehydrated (https://github.com/lukas2511/dehydrated)
#USE AT OWN RISK

#Imports
import json, requests, base64, sys
#imports variables used for script
from mynsconfig import *

__author__ = "Ryan Butler (techdrabble.com)"
__license__ = "GPL"
__version__ = "1.0.0"
__maintainer__ = "Ryan Butler"

#what to perform
whattodo = sys.argv[1]

def getAuthCookie(connectiontype,nitroNSIP,nitroUser,nitroPass):
   url = '%s://%s/nitro/v1/config/login' % (connectiontype, nitroNSIP)
   headers = {'Content-type': 'application/vnd.com.citrix.netscaler.login+json'}
   json_string = {
       "login":{
       "username":nitroUser,
       "password":nitroPass,
       }
   }
   payload = json.dumps(json_string)
   response = requests.post(url, data=payload, headers=headers, verify=False)
   cookie = response.cookies['NITRO_AUTH_TOKEN']
   nitroCookie = 'NITRO_AUTH_TOKEN=%s' % cookie
   return nitroCookie

def logOut(connectiontype,nitroNSIP,authToken):
   url = '%s://%s/nitro/v1/config/logout' % (connectiontype, nitroNSIP)
   headers = {'Content-type': 'application/vnd.com.citrix.netscaler.logout+json','Cookie': authToken}
   json_string = {
       "logout":{}
   }
   payload = json.dumps(json_string)
   response = requests.post(url, data=payload, headers=headers, verify=False)
   print "LOGOUT: %s" % response.reason
   
def SaveNSConfig(connectiontype,nitroNSIP,authToken):
   url = '%s://%s/nitro/v1/config/nsconfig?action=save' % (connectiontype, nitroNSIP)
   headers = {'Content-type': 'application/json','Cookie': authToken}
   json_string = {
       "nsconfig":{}
   }
   payload = json.dumps(json_string)
   response = requests.post(url, data=payload, headers=headers, verify=False)
   print "SAVE NS: %s" % response.reason

def sendFile(connectiontype,nitroNSIP,authToken,nscert,localcert,nscertpath):
   url = '%s://%s/nitro/v1/config/systemfile' % (connectiontype, nitroNSIP)
   headers = {'Content-type': 'application/vnd.com.citrix.netscaler.systemfile+json','Cookie': authToken}
   f = open(localcert, 'r')
   filecontent = base64.b64encode(f.read())
   json_string = {
   "systemfile": {
       "filename": nscert,
       "filelocation": nscertpath,
       "filecontent":filecontent,
       "fileencoding": "BASE64",}
   }
   payload = json.dumps(json_string)
   response = requests.post(url, data=payload, headers=headers, verify=False)
   print "CREATE CERT: %s" % response.reason

def respPol(connectiontype,nitroNSIP,authToken,nsresppol,token_filename):
   url = '%s://%s/nitro/v1/config/responderpolicy' % (connectiontype, nitroNSIP)
   headers = {'Content-type': 'application/json','Cookie': authToken}
   buildrule = 'HTTP.REQ.URL.CONTAINS(\"well-known/acme-challenge/%s\")' % token_filename
   print buildrule
   json_string = {
   "responderpolicy": {
       "name": nsresppol,
       "rule": buildrule,}
   }
   payload = json.dumps(json_string)
   response = requests.put(url, data=payload, headers=headers, verify=False)
   print "EDIT RESPONDER POLICY: %s" % response.reason

def respAct(connectiontype,nitroNSIP,authToken,nsrespact,token_value):
   url = '%s://%s/nitro/v1/config/responderaction' % (connectiontype, nitroNSIP)
   headers = {'Content-type': 'application/json','Cookie': authToken}
   buildtarget = "\"HTTP/1.0 200 OK\" +\"\\r\\n\\r\\n\" + \"%s\"" % token_value
   print buildtarget
   json_string = {
   "responderaction": {
       "name": nsrespact,
       "target": buildtarget,}
   }
   payload = json.dumps(json_string)
   response = requests.put(url, data=payload, headers=headers, verify=False)
   print "EDIT RESPONDER POLICY: %s" % response.reason

def removeFile(connectiontype,nitroNSIP,authToken,nscert,nscertpath):
   url = '%s://%s/nitro/v1/config/systemfile/%s?args=filelocation:%%2Fnsconfig%%2Fssl' % (connectiontype, nitroNSIP, nscert)
   headers = {'Content-type': 'application/vnd.com.citrix.netscaler.systemfile+json','Cookie': authToken}
   response = requests.delete(url, headers=headers, verify=False)
   print "DELETE NETSCALER CERTIFICATE: %s" % response.reason
   return response

def updateSSL(connectiontype,nitroNSIP,authToken, nscert, nspairname):
   url = '%s://%s/nitro/v1/config/sslcertkey?action=update' % (connectiontype, nitroNSIP)
   headers = {'Content-type': 'application/json','Cookie': authToken}
   json_string = {
   "sslcertkey": {
       "certkey": nspairname,
       "cert": nscert,
       "nodomaincheck": True,}
   }
   payload = json.dumps(json_string)
   response = requests.post(url, data=payload, headers=headers, verify=False)
   print "Update Netscaler CERT: %s" % response.reason

def createSSL(connectiontype,nitroNSIP,authToken, nscert, nspairname, nskey):
   url = '%s://%s/nitro/v1/config/sslcertkey' % (connectiontype, nitroNSIP)
   headers = {'Content-type': 'application/json','Cookie': authToken}
   json_string = {
   "sslcertkey": {
       "certkey": nspairname,
       "cert": nscert,
       "key": nskey,}
   }
   payload = json.dumps(json_string)
   response = requests.post(url, data=payload, headers=headers, verify=False)
   print "Create Netscaler CERT: %s" % response.reason

def createSSLCA(connectiontype,nitroNSIP,authToken,nscert,nspairname):
   url = '%s://%s/nitro/v1/config/sslcertkey' % (connectiontype, nitroNSIP)
   headers = {'Content-type': 'application/json','Cookie': authToken}
   json_string = {
   "sslcertkey": {
       "certkey": nspairname,
       "cert": nscert,}
   }
   payload = json.dumps(json_string)
   response = requests.post(url, data=payload, headers=headers, verify=False)
   print "Create Netscaler CA CERT: %s" % response.reason

def linkSSL(connectiontype,nitroNSIP,authToken, nschainname, nspairname):
   url = '%s://%s/nitro/v1/config/sslcertkey?action=link' % (connectiontype, nitroNSIP)
   headers = {'Content-type': 'application/json','Cookie': authToken}
   json_string = {
   "sslcertkey": {
       "certkey": nspairname,
       "linkcertkeyname": nschainname,}
   }
   payload = json.dumps(json_string)
   response = requests.post(url, data=payload, headers=headers, verify=False)
   print "Link Netscaler CERTS: %s" % response.reason

authToken = getAuthCookie(connectiontype,nitroNSIP,nitroUser,nitroPass)
if whattodo == "save":
   localcert = sys.argv[2]
   print "Updating Netscaler Certificate"
   removeFile(connectiontype,nitroNSIP,authToken,nscert,nscertpath)
   sendFile(connectiontype,nitroNSIP,authToken,nscert,localcert,nscertpath)
   updateSSL(connectiontype,nitroNSIP,authToken, nscert, nspairname)
   SaveNSConfig(connectiontype,nitroNSIP,authToken)
elif whattodo == "challenge":
   print "Editing Challenge Policy"
   token_filename = sys.argv[2]
   token_value = sys.argv[3]
   respPol(connectiontype,nitroNSIP,authToken,nsresppol,token_filename)
   respAct(connectiontype,nitroNSIP,authToken,nsrespact,token_value)
elif whattodo == "create":
   localcert = sys.argv[2]
   localkey = sys.argv[3]
   localchain = sys.argv[4]
   print "Create Netscaler Certificate"
   sendFile(connectiontype,nitroNSIP,authToken,nscert,localcert,nscertpath)
   sendFile(connectiontype,nitroNSIP,authToken,nskey,localkey,nscertpath)
   sendFile(connectiontype,nitroNSIP,authToken,nschain,localchain,nscertpath)
   createSSL(connectiontype,nitroNSIP,authToken, nscert, nspairname, nskey)
   createSSLCA(connectiontype,nitroNSIP,authToken, nschain, nschainname)
   linkSSL(connectiontype,nitroNSIP,authToken, nschainname, nspairname)
   SaveNSConfig(connectiontype,nitroNSIP,authToken)
logOut(connectiontype,nitroNSIP,authToken)
