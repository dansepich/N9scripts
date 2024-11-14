import requests
import json
import simplejson as json
from enum import Enum
from datetime import datetime, timedelta
import sys
import json
from unicodedata import name
import rfc3339
import uuid


#~~~~~Account Details~~~~~#
URL = "https://app.nobl9.com"
ORGANIZATION = "<YOUR ORG HERE>"
#Grab this from your SLO CTL file. 
CLIENT_ID = "<YOUR CLIENTID HERE>"
CLIENT_SECRET = "<YOUR CLIENT SECRET HERE>"
#Go get a token. 
TOKEN = requests.post(
        f"{URL}/api/accessToken",
        auth=(CLIENT_ID, CLIENT_SECRET),
        headers={"organization": ORGANIZATION},
    )
if TOKEN.status_code == 200:
    print("We have a Token")
else:
    print("Somthing is Broken")
    print(TOKEN.text)
    exit(1)
TOKEN = TOKEN.json()["access_token"]


#This is where custom logic to tap into change management could be implemented
def getChanges():
    #Label values go here
    return ['Boston', 'Dallas']

def deployAnnotation(sloName, project, annotationName, annotationData):
    # Set Annotation time period. If you want to set a particular time, comment out line 48 and 49 and go to line 52 to set your specific time. 
    now = datetime.utcnow()
    since = now + timedelta(minutes=5) #  5 mimutes, change the minutes= to something longer if you like.
    print(now)
    print(since)

    # Uncomment these to use the auto set time from now to plus what ever you set above. (line 49)
    TO = rfc3339.rfc3339(now)
    FROM = rfc3339.rfc3339(since)
    SLO_ANNOTATION = {'slo' : sloName, 'project' : project, 'name' : annotationName, 'description' : annotationData, 'startTime' : TO, 'endTime' : FROM}
    r = requests.post(
        f"{URL}/api/annotations",
        data=json.dumps(SLO_ANNOTATION),
        headers={
            "authorization": f"Bearer {TOKEN}",
            "organization": ORGANIZATION,
        },
    )

def main():
    r = requests.get(
        f"{URL}/api/v1/slos",
        headers={
            "authorization": f"Bearer {TOKEN}",
            "organization": ORGANIZATION,
        },
    )
    #Checks for labels containing string values returned from the getChange() function and applies annotations to those SLOs
    if r.status_code == 200:
        jsonObject = r.json()
        for change in getChanges():
            print(change)
            for value in jsonObject['data']:
                if 'labels' in str(value):
                    if change in str(value):
                        deployAnnotation(str(value['name']), str(value['project']), str(uuid.uuid4()), "Hello from Python!")
    else:
        print("Something failed")
        print(r.text)
        exit(1)

if __name__ == '__main__':
        main()
