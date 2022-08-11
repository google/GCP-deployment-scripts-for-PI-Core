architecture       = "[Please enter HA or Non-HA]"
region             = "[Please enter region for deployment supported by Google Cloud]"
project_id         = "[Please enter project ID for deployment]"
ad-cidr            = "[Please enter CIDR range for Google Managed AD from: 10.0.0.0/20, 172.16.0.0/20, 192.168.0.0/20]"
compute-multi-cidr = "[Please enter CIDR range for network from: 10.0.0.0/20, 172.16.0.0/20, 192.168.0.0/20]"
ad-dn              = "[Please enter Domain Name eg: test.com]"
storage            = "[Please enter the bucket name containing the executable files]"
creds              = "[Your credential file name within the terraform directory. See Step 3 in the Before you Deploy section]"
tf_sa              = "[Enter email id of the service account use to deploy terraform with proper permission]"
epsec              = "[Not yet implemented - Events per second. For non-HA deployments, 10,000 events per second is used]"
valid_domain       = "[Enter 'Yes' if you have valid public domain, enter 'No' if you don't]"
ssl-dn             = "[If you have selected Yes for point valid_domain, add your valid public domain name and Google will manage the certificate. If No, use the mentioned dummy domain. If you have a separate certificate (self-signed or otherwise), please refer to Post Deployment Steps]"
zones              = ["us-east1-b","us-east1-c","us-east1-d"]
OS		   = "[Enter Windows, Linux, or MacOS depending on which OS you're using to deploy the script]"	