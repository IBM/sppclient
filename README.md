# sppclient

sppclient is a Python module that aims to simplify interaction with SPP's REST API.



This module can be used for automation of testing procedures or tasks on the SPP appliance



The module is registered on PyPI and can be installed with:


 $ pip install sppclient


# Usage

When writing a script using sppclient import with:


 import spplib.sdk.client as client
 
 
To create a session object:


 session = client.SppSession("sppHost", "sppUsername", "sppPassword")
 
 
 session.login()
 

To interact with SPP API:


 client.SppAPI(session, 'resource_endpoint').get()


# Sample commands to run included sample scripts.

$ python3 script.py -h (This command provides a list of input parameters needed to run the script)


$ python3 createsite.py --host="https://x.x.x.x:8443" --user="admin" --pass="password" --sitename="samplesite" --sitedesc="This is a sample site"



$ python3 runjob.py --host="https://x.x.x.x:8443" --user="admin" --pass="password" --jobname="samplejob"



<sub>All materials are provided for informational purposes only and officially not supported, and is provided AS IS without warranty of any kind, express or implied. IBM shall not be responsible for any damages arising out of the use of, or otherwise related to, these materials.  Nothing contained in these materials is intended to, nor shall have the effect of, creating any warranties representations from IBM or its suppliers or licensors, or altering the terms and conditions of the applicable license agreement  governing the use of IBM software.</sub>
