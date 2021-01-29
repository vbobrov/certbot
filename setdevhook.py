#!/usr/bin/env python3
import os
import subprocess
import sys
import re
import signal
from webexteamssdk import WebexTeamsAPI

print(sys.argv)
ltProcess=subprocess.Popen(['lt',"-p",sys.argv[1]],stdout=subprocess.PIPE)
ltOut=ltProcess.stdout.readline().decode()
ltUrl=re.findall(r"your url is: (.*)",ltOut)[0]
print(f"url is {ltUrl}")
wbxApiToken=os.getenv('WEBEX_TEAMS_DEV_TOKEN')
wbxApi=WebexTeamsAPI(access_token=wbxApiToken)
wbxHooks=wbxApi.webhooks.list()
for wbxHook in wbxHooks:
	if "loca.lt" in wbxHook.targetUrl:
		newUrl=re.sub(r"https://[^\/]+/(\S+)",rf"{ltUrl}/\1",wbxHook.targetUrl)
		print(f"Updating {wbxHook.id} from {wbxHook.targetUrl} to {newUrl}")
		wbxApi.webhooks.update(wbxHook.id,targetUrl=newUrl)
input("Press <ENTER> to exit:")
ltProcess.kill()
