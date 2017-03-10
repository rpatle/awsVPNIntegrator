# awsVPNIntegrator
Create hybrid cloud environment with AWS and your local datacenter.

Component of VPN
1. Virtual Privage Gateway
	Amazon side VPN concentrator.
2. Customer Gateway
	Physical device
	
	
Steps 

1. Create Customer Gateway	
	Name
	Routing
          static with IP
          dynamic with IP and BGP

2. Create Virtual Private Gateway
	Name
	then attach it to VPC.
	
3. instance in VPC should be able to reach customer gateway.
	Select route table for that VPC
	EDIT with Routes.. and save VPC ID (point 2) save it to destination.
 
4. Edit Security Group
	inbound traffic SSH, RPD, ICMP, where source is your network.
 
5. Create VPN Connection and configure customer gateway
	name
	customer private gateway
	virtual private gateway
	routing option : static
