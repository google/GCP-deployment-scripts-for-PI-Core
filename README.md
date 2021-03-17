## Description

GCP deployment scripts for PI Core are a set of deployment scripts created by Quantiphi Inc. in collaboration with Google and OSIsoft to install various PI System elements on Google's VMs. The deployment scripts are automated reference deployments that use Terraforn templates to deploy key PI technologies on GCP, following OSIsoft and GCP best practices.

This deployment guide provides step-by-step instructions for deploying a PI System on the GCP environment for a new installations of the PI System. OSIsoft PI System on GCP is intended for use by existing OSIsoft customers to support quick and iterative testing and prototyping purposes. As development environments move to the cloud, PI Admins need easy and quick ways to deploy resources for their testing cycles. OSIsoft PI System on GCP provides an easy way to deploy a full PI System repeatedly and reliably to the Google Cloud for this type of development cycle.

>  Note: The deployment samples are meant for testing and prototyping purposes, and not meant to be used within a production environment

The scripts provided in this repository leverage Terraform and Windows Powershell for fresh installations of the following compoenents of the PI System:
*  PI Data Archive (DA)
*  PI Asset Framework (AF)
*  SQL Server 
*  Analysis/Notification
*  PI Integrator
*  PI Web API (and its OMF end-point)
*  PI Vision
*  SQL Server Database

**Use-case:** *As a user, I should be able to install and host the PI System and Integrator on Google Cloud’s Compute instances for lower infrastructure costs and higher availability which is automated through Infrastructure as Code (IaC)*

## Deployment Architecture for OSIsoft PI System on GCP

GCP deployment scripts for PI Core cater to both High Availability and Non-High Availability scenarios to manage different traffic loads and other user requirements for scale.

### Non-HA Architecture

Suited best for less than ~10,000 events or requests per second, the Non-HA topology divided the PI System components into 3 subnets on GCP

![](images/Non-HA_Architecture.png)

The Non-HA topology utilizes AMD's **n2d-standard-2** vCPUs (consisting of 2 vCPUs and 8GB memory). For more information on Google Cloud and AMD, please refer to [this link](https://cloud.google.com/blog/products/compute/announcing-the-n2d-vm-family-based-on-amd)

* Subnet 1: The MS SQL database is deployed separately to ensure isolation
* Subnet 2: The PI Server (AF, DA, Analysis & Notifications) is deployed on a Compute instance
* Subnet 3: PI Vision, PI Web and Web OMF APIs and the PI Integrator are deployed on a Compute engine instance. 
* Subnet 3: Bastion server on a Compute instance separate from PI Vision, Web and Integrator. Cloud Load Balancer (HTTPS) is provisioned to access the PI Vision Server from the internet

> **Note:**
> *  MS SQL Server requires connectivity with the PI AF and DA servers for storing information regarding the archived IoT data. Alongwith MS SQL, the PI Vision and PI integrator must also have connectivity with the AF and DA servers.
> *  Google Managed AD has been used to manage authentication and authorisation. Managed Service for Microsoft Active Directory (AD) is a highly available, hardened Google Cloud service running actual Microsoft AD that enables you to manage authentication and authorization for AD-dependent workloads, automate AD server maintenance and security configuration, and also connect your on-premises AD domain to the cloud.
> * However this solution caters strictly to customers with AD that is - or plans to be - on Google Cloud, and does not reside on-premise

### HA Architecture

Best suited for ~20,000 events per second. If selected, an HA architecture spans two Availability Zones, each zone consisting of one or more discrete data centers, each with redundant power, networking, and connectivity, housed in separate facilities.

![](images/HA_Architecture.png)

The HA topology utilizes AMD's *n2d-standard-4* vCPUs (consists of 4 vCPUs and 16GB memory). For more information on Google Cloud and AMD, refer to [this link](https://cloud.google.com/blog/products/compute/announcing-the-n2d-vm-family-based-on-amd)

 The PI System components for HA are deployed in 10 different subnets spanned across 3 zones (2 zones for mirroring PI components, and 1 zone for the Windows Server Failover Cluster). Described below is the logical separation of the PI components and resources across these subnets and zones.

* The MS SQL Database is deployed in a separate subnet for isolation. The MS SQL server is deployed as SQL server “Always on” availability groups. SQL servers can be accessed via SQL listener
* 2 Compute Engine instances are deployed in two different subnets behind GCP Internal Load balancer. These instances are running PI Asset Framework and Data archive services
* 2 Compute Engine instances are deployed in two different subnets behind GCP Internal (TCP) Load Balancer. These instances run PI Server: Analysis and Notification services and the PI Integrator. These two instances are in Windows Server Failover Cluster with Witness configured on different a subnet and zone (Zone C) in a Compute Engine instance
* 2 Compute Engine instances are running PI Vision and PI Web API as one application
* 2 Compute Engine instances are running the PI Web OMF endpoint as one application. These two applications are running behind the GCP HTTPS Load Balancer for connectivity from the internet
* 2 Bastion servers are deployed in two zones for connecting to the application server on a private IP address
* Google Managed AD has been used to manage authentication and authorisation. Managed Service for Microsoft Active Directory (AD) is a highly available, hardened Google Cloud service running actual Microsoft AD that enables you to manage authentication and authorization for AD-dependent workloads, automate AD server maintenance and security configuration, and also connect your on-premises AD domain to the cloud

(#code-description)

> **Note:**
> * The MS SQL Server requires connectivity with the PI AF and DA servers for storing information regarding the archived IoT data
> * The PI Vision and PI integrator must also have connectivity with the AF and DA servers
> * The PI Asset Framework and Data Archive services can be accessed with the DNS name of the internal TCP Load Balancer of AF and DA (Subnet 9)
> * Analysis and Notification services can be accessed with the DNS name of the internal TCP Load Balancer of Analysis and Notification (Subnet 10)
> * This solution caters strictly to customers with AD that is - or plans to be - on Google Cloud, and does not reside on-premise



## Prerequisites for Deployment

### Software Requirements

*   A Google Cloud project with billing enabled. For more information on creating a project, refer to the official [Google Cloud Platform documentation](https://cloud.google.com/resource-manager/docs/creating-managing-projects)
*   PI Components Installation kit. Download the necessary software mentioned below through the [OSIsoft Customer Portal.](https://customers.osisoft.com/s/)

         1. PI Server installation kit -  PI-Server_2018-SP3-Patch-1_.exe
         2. PI Vision installation kit - PI-Vision_2019-Patch-1_.exe
         3. PI Web installation kit - PI-Web-API-2019-SP1_1.13.0.6518_.exe
         4. PI Integrator installation kit - OSIsoft.PIIntegratorBA_2020_ADV_1000_2.3.0.425_.exe
         5. Temporary PI license    


 
*  Terraform with version >= 0.13. To install Terraform, head to the [download manager](https://www.terraform.io/downloads.html)

### Specialized Knowledge

As highlighted in the architectures above, the PI System is installed in multiple subnets/zones on various Google Compute instances based on OSIsoft best practices. Before starting installation, it is recommended that users familiarize themselves with the GCP resources provisioned to manage this deployment. Refer to the links below for a deeper expanation:

*  [**Google Compute Engine**](https://cloud.google.com/compute/docs) - Computing infrastructure in predefined or custom machine sizes on GCP. Compute Engine offers predefined virtual machine configurations for every need and are used to host the PI System and Domain Controller
*  [**Cloud Load Balancing**](https://cloud.google.com/load-balancing/docs) - Distributes load-balanced compute resources in single or multiple regions (closer to users) meets high availability requirements. It can put your resources behind a single anycast IP and scale your Compute resources up or down for your applications
*  [**Cloud NAT**](https://cloud.google.com/nat/docs/overview) - Cloud NAT (network address translation) allows Google’s VM instances without external IP addresses and private Kubernetes Engine clusters to send outbound packets to the internet and receive any corresponding established inbound response packets
*  [**Google Managed Active Directory**](https://cloud.google.com/managed-microsoft-ad/docs) - Managed Service for Microsoft Active Directory (AD) is a highly available, hardened GCP service running actual Microsoft AD that allows you to manage authentication and authorization for AD-dependent workloads, automate AD server maintenance and security configuration, and connect any on-premises AD domain to the cloud. *For this engagement, it is assumed that customers ensure their AD is on Google Cloud, and not on-premise*
*  [**Cloud VPC**](https://cloud.google.com/vpc/docs/vpc) - Provides connectivity for VM instances, offers native Internal TCP/UDP Load Balancing and proxy systems for Internal HTTP(S) Load Balancing, connects to on-premises networks using Cloud VPN tunnels and Cloud Interconnect attachments and distributes traffic from Google Cloud external load balancers to backends
*  [**Cloud Armor**](https://cloud.google.com/armor/docs) - Protects infrastructure and applications from distributed denial-of-service (DDoS) attacks
*  [**Cloud DNS**](https://cloud.google.com/dns/docs) - USed to publish your domain names by using Google's infrastructure for production-quality, high-volume DNS services
*  [**Google Cloud Storage (GCS)**](https://cloud.google.com/storage/docs) - You can use GCS buckets for a range of scenarios including serving website content, storing data for archival and disaster recovery, or distributing large data objects to users via direct download

### High Availability Consideration

The High Availability configuration for takes advantage of dynamic capabilities of the GCP. This allows for easy scaling of various Google Compute Engine types and storage capacity as your PI System grows in scope and scale. 

Before deploying OSIsoft PI System on GCP, users must decide whether deploy the PI System in an HA environment or in a non-HA one. While the HA architecture provides improved resiliency against outages and failure it also requires more GCP resources than a non-HA configuration. **Ensure this is evaluated during the planning process i.e. before deployment.**

**PI System in High Availability (HA):** This option creates two instances of almost each application, and is recommended for traffic of around 20,000 events per second. It is the responsibility of the user to ensure that the subnets are correctly configured in different availability zones to ensure true high availability of resources

**PI System without High Availability (non-HA):** This option creates only a single instance of each application, uses fewer GCP resources, and is best suited for traffic of around 10,000 events per second.


## Deployment Procedure

### Before you Deploy

#### 1. Download the code on your local machine

Click Clone or Download and then Download Zip to download the contents of this GitHub repository, and select the target location on your local machine

OR use the following git command: 

         git clone


#### 2. Creating Cloud Storage Buckets on GCP


*  Users must first create **two** Cloud Storage (GCS) buckets. The name of these buckets will be passed during deployment:

The first one will be used to store PI server installation executables mentiond in the "Software Requirements" section.
The folder structure for this bucket will be as follows:

    bucket  -> pivision - this will contain the .exe for PI Vision - PI-Vision_2019-Patch-1_.exe
            -> piserver  - this folder will containe the .exe for PI Server and the temporary license file - PI-Server_2018-SP3-Patch-1_.exe
            -> piserver -> pivision-db-files - This folder contains all the "SQL scripts" and ".bat" files needed for installation of the PI Vision DB
            -> piweb - this will contain the .exe for the PI Web API (and OMF) - PI-Web-API-2019-SP1_1.13.0.6518_.exe
            -> integrator - this will contain the .exe for the PI Integrator - OSIsoft.PIIntegratorBA_2020_ADV_1000_2.3.0.425_.exe

>  Note: The folder names are case sensitive


*  The second GCS bucket passed to the remote Terraform backend (as shown in later stages of this section).


#### 3. Terraform
1.  Once your code has been downloaded or cloned as mentioned in the first step, head over to the **terraform** directory of the repo
2.  Within the directory, edit the **"provider.tf"** file. Within that file, change the following for the **backend block**:
         a. Enter the name of the GCS bucket created in step above to store the **.tfstate** file
         b.((Optional) Enter a prefix
         c. Edit the credential file name that is present inside the Terraform directory
3. Within the terraform directory, add the Service Account JSON Key (credential file) with the following permissions:

            [
            "roles/compute.admin",
            "roles/secretmanager.admin",
            "roles/resourcemanager.projectIamAdmin",
            "roles/iam.serviceAccountAdmin",
            "roles/managedidentities.admin",
            "roles/managedidentities.domainAdmin",
            "roles/compute.loadBalancerAdmin",
            "roles/compute.storageAdmin",
            "roles/iam.serviceAccountUser",
            "roles/resourcemanager.projectMover"
            ]


#### 4. Update the gcloud SDK on your local machine

Google Cloud SDK can be installed through [this documentation.](https://cloud.google.com/sdk/docs/install) 

Update gcloud SDK configurations on your local machines along with the alpha and beta componets. Use the following commands to set the GCP project:

       [gcloud config set project [project name]] //refers to the name of the project where the scripts are to be be deployed
       [gcloud components install alpha]
       [gcloud components install beta]
       [gcloud auth activate-service-account [service account email] --key-file=KEY_FILE]


#### 5. Enable APIs

Ensure the APIs listed below are enabled at least 10 minutes before the Terraform deployment. These are required when enabling billing for service accounts.

                    [
                    "compute.googleapis.com",
                    "storage-component.googleapis.com",
                    "iam.googleapis.com",
                    "iamcredentials.googleapis.com",
                    "managedidentities.googleapis.com",
                    "secretmanager.googleapis.com",
                    "dns.googleapis.com",
                    "cloudresourcemanager.googleapis.com"
                    ]
                    
#### 6. Network

Ensure that **no existing network** is be present withing RFC-1918 CIDR ranges. Users can verify this by heading to their GCP console, into "VPC Network" under the "Networking" category under the IP Ranges Column. For more information, please visit this [documentation link for Google Managed AD](https://cloud.google.com/managed-microsoft-ad/docs/selecting-ip-address-ranges#using_a_24_range_size). 

 
 
### Steps to Deploy the OSISoft PI System on GCP (non-HA)

Once all the steps in the previous section are complete, the Terraform deployment can begin

* Ensure you in the **terrafom** directory of your repo, where the **readme.txt** is present for reference. This location also has  the **main.tf** file.
* Run the commands below for deployment


        terrafom init
        terraform plan
        terraform apply

*  During **terraform plan** and **terraform apply** steps, Terraform will ask for values for the variables mentioned below (left). Please fill/edit in the values for each variable as per your preference (right):


            1. architecture       = Non-HA / HA
            2. region             = "us-east1" [You can select any region that is supported by GCP]
            3. project_id         = "osi-pi-test-2" [Your project ID]
            4. ad-cidr            = "172.16.0.0/20" [RFC 1918 valid ranges supported]
            5. compute-multi-cidr = "10.0.0.0/20" [RFC 1918 valid ranges supported]
            6. ad-dn              = "osipi.com"
            7. storage            = "osi-pi-test-2" [Your bucket name consisting of the powershell executable files]
            8. creds              = "creds.json" [Your credential file name within the the terraform directory. See Step 3 in the "Before you Deploy" section]
            9. tf_sa              = "gcp-devops@appspot.gserviceaccount.com"
            10. epsec             = 10000 / 20000 [events per second. For non-HA deployments, 10,000 events per second is used]
            11. valid_domain      = Yes / No
            12. ssl-dn            = "osi.qdatalabs.com" [If you have selected "Yes" for point 11, add your valid public domain name and Google will manage the certificate. If "No", use the mentioned dummy domain. If you have a separate certificate (self-signed or otherwise), please refer to "Post Deployment Steps"]


* Once solution is deployed, verify if the installation is complete by checking success files flags inside the GCS bucket for your executables (See Step 2 in "Before you Deploy"). In this bucket you will see a set of 6 text files called success files/flags that indicate the completion of the installation process:
    * sql_success.txt
    * piserver_success.txt
    * integrator_success.txt
    * vision_success.txt
    * omf_success.txt
    * db_success.txt

## Post Deployment Steps

Now that you have successfully deployed your PI System executables, you will have to test them to ensure they are running correctly. Before you begin running your PI System components, follow the pre-requisites and configuration changes below:

#### 1. (Optional) If Users Have Their Own Certificate

This step is only applicable to users who do not immediately have a valid domain but would prefer to have their own certificate over a Google Managed one. 

**Pre-requisite:**
While creating the certificate make sure to give the **Common Name** (e.g. the IP of the Load Balancer or Server FQDN etc.)
 
**Configuration:**
Below are the steps to upload the certificate on the GCP Cloud Console 
* In the GCP Cloud Console, open the **Load Balancing page** from the navigation menu
* Select the Load Balancer with the following name: **url-map-pivii** and click on **Edit** to change the configurations  
* Select the **frontend configuration** and click the edit icon on the right side of the page 
* Within that certificate dropdown , click on **Create a new Certificate**
* In the Public Key certificate section, upload the cert.pem from your local machine
* In the Private Key certificate section, upload the key.pem from your local machine
* Click on **Create**
* Finally, select **Update** to update the changes


#### 2. Security listing of IPs for Cloud Armor

This step is required to ensure the appropriate users are listed in the Cloud Armor rules so that the load balancer accepts the corresponding IP addresses. Change the configurations through the following steps:

**A) For Cloud Armor**
* In your GCP Cloud Console, go to the Cloud Armor page from the navigation menu
* Select the following policy: **policy-pivii** 
* To edit the rules there, select the rule that has the following description: **“first rule”** and click on the edit icon on the right of the table 
* Under the **Match** section within that page, add your Public IP Address besides the already existing IP. Ensure they are separated by “,” 
* Update the rule

**B) PI Vision Authentication**
This can be done in two ways: through <basicAuthenticaltion> or using Powershell. 
* Basic Authentication: Refer to the [following documentation](https://docs.microsoft.com/en-us/iis/configuration/system.webserver/security/authentication/basicauthentication) provided by Microsoft to undergo steps for basic authentication
* With Powershell Scripts:
  * Run PowerShell as an administrator
  * Run the following command: **Enable-WindowsOptionalFeature -Online -FeatureName IIS-BasicAuthentication**

Make changes to the Configuration:
* Follow the steps present in this official PI Vision document: [Enable Basic Authentication: PI Vision 2019](https://livelibrary.osisoft.com/LiveLibrary/content/en/vision-v3/GUID-9CF76AC8-BBB9-4E1C-A77C-63373901E64A#addHistory=true&filename=GUID-4B33BAFA-A923-4550-B3DC-CAD83E3C0587.xml&docid=GUID-9CF76AC8-BBB9-4E1C-A77C-63373901E64A&inner_id=&tid=&query=&scope=&resource=&toc=false&eventType=lcContent.loadDocGUID-9CF76AC8-BBB9-4E1C-A77C-63373901E64A)
* Go to your machine's Internet Information Services (IIS) Manager and click on the Default Website in the Connections panel. Restart this connection (on the right side of the window)


## Destroy the deployment

* To destroy the infrastucture, run the command before on Terraform: 

        terrafom destroy

>  Note: destroy will not delete lables set on the project. You will have to manually delete those labels by navigating to Project Settings->Labels

**This is not an officially supported Google or OSIsoft product.**

 




