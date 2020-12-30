## Automated ELK Stack Deployment

The files in this repository were used to configure the network depicted below.

!(Images/NetworkDiagram.png)

These files have been tested and used to generate a live ELK deployment on Azure. They can be used to either recreate the entire deployment pictured above. Alternatively, select portions of the __filebeat-config.yml__ file may be used to install only certain pieces of it, such as Filebeat.

This document contains the following details:
- Description of the Topologu
- Access Policies
- ELK Configuration
  - Beats in Use
  - Machines Being Monitored
- How to Use the Ansible Build


### Description of the Topology

The main purpose of this network is to expose a load-balanced and monitored instance of DVWA, the D*mn Vulnerable Web Application.

Load balancing ensures that the application will be highly __available__, in addition to restricting __direct access__ to the network.

Integrating an ELK server allows users to easily monitor the vulnerable VMs for changes to the __logs__ and system __metrics__.

The configuration details of each machine may be found below.

| Name     | Function | IP Address | Operating System |
|----------|----------|------------|------------------|
| Jump-Box-Provisioner | Gateway | 10.0.1.4 | Linux |
| ESS-LoadBalancer | Load Balancer | 104.211.58.162 | - |
| Web-1 | Web Server | 10.0.1.5 | Linux |
| Web-2 | Web Server | 10.0.1.6 | Linux |
| ESS-ELK | ELK Server | 10.1.0.4 | Linux |

### Access Policies

The machines on the internal network are not exposed to the public Internet. 

Only the __Jump Box__ machine can accept connections from the Internet. Access to this machine is only allowed from the following IP addresses:

| IP Address | Machine ID |
|-------------|--------------|
| 99.229.18.174 | Personal Workstation |


Machines within the network can only be accessed by __ssh__.

The __ELK VM__ can be accessed by the above Personal Workstation, but only via TCP ports 5601, 9200, and 5044 for Kibana access.

A summary of the access policies in place can be found in the table below.

| Name     | Publicly Accessible | Allowed IP Addresses |
|----------|---------------------|----------------------|
| Jump Box | Yes | 99.229.18.174, 10.0.1.0/24 |
| Web-1 | No | 10.0.1.0/24 |
| Web-2 | No | 10.0.1.0/24 |
| ESS-ELK | Yes | 99.229.18.174, 10.0.0.0/15 |

### Elk Configuration

Ansible was used to automate configuration of the ELK machine. No configuration was performed manually, which is advantageous because if another ELK machine is needed for redundancy or replacement, the setup of the new machine can be done quickly by executing the Ansible playbook.

The playbook implements the following tasks:

- Install Docker
- Install Python3
- Configure VM to use maximum memory (RAM)
- Download, install, and launch Docker ELK container

The following screenshot displays the result of running `docker ps` after successfully configuring the ELK instance.

![TODO: Update the path with the name of your screenshot of docker ps output](Images/docker_ps_output.png)

### Target Machines & Beats
This ELK server is configured to monitor the following machines:
- _TODO: List the IP addresses of the machines you are monitoring_

We have installed the following Beats on these machines:
- _TODO: Specify which Beats you successfully installed_

These Beats allow us to collect the following information from each machine:
- _TODO: In 1-2 sentences, explain what kind of data each beat collects, and provide 1 example of what you expect to see. E.g., `Winlogbeat` collects Windows logs, which we use to track user logon events, etc._

### Using the Playbook
In order to use the playbook, you will need to have an Ansible control node already configured. Assuming you have such a control node provisioned: 

SSH into the control node and follow the steps below:
- Copy the _____ file to _____.
- Update the _____ file to include...
- Run the playbook, and navigate to ____ to check that the installation worked as expected.

_TODO: Answer the following questions to fill in the blanks:_
- _Which file is the playbook? Where do you copy it?_
- _Which file do you update to make Ansible run the playbook on a specific machine? How do I specify which machine to install the ELK server on versus which to install Filebeat on?_
- _Which URL do you navigate to in order to check that the ELK server is running?

_As a **Bonus**, provide the specific commands the user will need to run to download the playbook, update the files, etc._