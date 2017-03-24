'''

Steps 

1. Create Customer Gateway  
    Name
    Routing -   static with IP
        
2. Create Virtual Private Gateway

3. instance in VPC should be able to reach customer gateway.
    Select route table for that VPC
    EDIT with Routes.. and save VPG ID (point 2) save it to destination.
 
4. Edit Security Group
    inbound traffic SSH, RDP, ICMP, where source is your network.
 
5. Create VPN Connection and configure customer gateway
    name
    customer private gateway
    virtual private gateway
    routing option : static

'''

import boto, boto3, botocore
from boto3 import client, resource
import boto.ec2
import time, os, sys
import urllib2, json
import boto.ec2.networkinterface

import logging
DoLog = logging.getLogger(__name__)

do_not_retry = ['AccessDenied', 'UnauthorizedOperation']

'''decorator function for retry.'''
def retry_this(connnect_to_data_center_func):
    def connnect_to_data_center_wrapper(*args, **kwargs):
        retry_taken = 0
        retry_available = 5 # how many time to retry particular function.
        sleep_before_retry = 20 # in seconds
        while retry_taken < retry_available:
            try:
                return connnect_to_data_center_func(*args, **kwargs)
            except botocore.exceptions.ClientError, fault:
                if fault.response['Error']['Code'] in do_not_retry:
                    DoLog.error("Not retrying since error is not retryable for : %s", connnect_to_data_center_func.__name__)
                    raise
                else:
                    DoLog.info("Retrying in %s seconds.", str(sleep_before_retry))
                    retry_taken += 1
                    time.sleep(sleep_before_retry)
            except boto.exception.EC2ResponseError, fault:
                if fault.response['Error']['Code'] in do_not_retry:
                    DoLog.error("Not retrying since error is not retryable for : %s", connnect_to_data_center_func.__name__)
                    raise
                else:
                    DoLog.info("Retrying in %s seconds.", str(sleep_before_retry))
                    retry_taken += 1
                    time.sleep(sleep_before_retry)
            except Exception, fault:
                DoLog.error("Not retrying any more since error is not retryable for Fn: %s", connnect_to_data_center_func.__name__)
                raise
        DoLog.traceback(fault)
        raise
    return connnect_to_data_center_wrapper

@retry_this
def get_aws_region_name():
    '''
    description: get the region name in which current aws instance is deployed ie self
    '''
    region_name = None
    try:
        response = urllib2.urlopen('http://169.254.169.254/latest/dynamic/instance-identity/document/')
        result = json.load(response)
        region_name = result['region']
        DoLog.info("<get_region_name>: successful: %s", region_name)
        return region_name
    except Exception, fault:
        DoLog.error("<get_region_name>: Error: %s", str(fault))
        DoLog.traceback(fault)
        raise Exception("error in get region name. Error: %s" % str(fault))

class ConnnectToDataCenter():
    def __init__(self, aws_key = None, aws_secret_key = None, region_name = None):
        '''
        If you run this code in IMRole enabled instance with suitable permissions
        It won't be required to provide aws_key and aws_secret_key
        '''
        self.aws_key = aws_key
        self.aws_secret_key = aws_secret_key

        if region_name == None:
            self.region_name = get_aws_region_name()
        else:
            self.region_name = region_name

    @retry_this
    def connect_ec2(self):
        '''
        description: function used by boto to get connect to ec2.
        '''
        try:
            DoLog.info("<connect_ec2> Creating ec2 connection.")
            ec2_conn = boto.ec2.connect_to_region(self.region_name, aws_access_key_id=self.aws_key, aws_secret_access_key=self.aws_secret_key)
            DoLog.info("<connect_ec2> Created ec2 connection successfully.")
            return ec2_conn
        except Exception, fault:
            err_msg = 'error in connect to region: %s, Error: %s' %(self.region_name, str(fault))
            DoLog.error('<connect_ec2>: %s', err_msg)
            DoLog.traceback(fault)
            raise

    @retry_this
    def _get_ec2_client(self, refresh_ec2_client = True):
        '''
        description: function used by boto to get ec2 client object using boto3
        '''
        try:
            #DoLog.info("<_get_ec2_client> getting ec2 client.")
            ec2_client = client('ec2', region_name = self.region_name, aws_access_key_id=self.aws_key, aws_secret_access_key=self.aws_secret_key)
            DoLog.info("<_get_ec2_client> ec2 client created successfully.")
            return ec2_client
        except Exception, fault:
            err_msg = 'error to get ec2_client for region: %s, Error: %s' %(self.region_name, str(fault))
            DoLog.error("<_get_ec2_client>: %s", err_msg)
            DoLog.traceback(fault)
            raise

    @retry_this
    def _get_ec2_resource(self):
        '''
        description: function used by boto to get ec2_resource object using boto3
        '''
        try:
            #DoLog.info("<_get_ec2_resource> getting ec2 client.")
            ec2_resource = resource('ec2', region_name = self.region_name, aws_access_key_id=self.aws_key, aws_secret_access_key=self.aws_secret_key)
            DoLog.info("<_get_ec2_resource> ec2 client created successfully.")
            return ec2_resource
        except Exception, fault:
            err_msg = 'error to get ec2_resource for region: %s, Error: %s' %(self.region_name, str(fault))
            DoLog.error("<_get_ec2_resource>: %s", err_msg)
            DoLog.traceback(fault)
            raise

    def create_customer_gateway(self, public_ip):
        '''
        public_ip is Internet routable IP address for the customer gateway's outside interface. 
        The address must be static.
        '''
        try:
            #ip_address_validation(public_ip)
            ec2_client = self._get_ec2_client()
            response = ec2_client.create_customer_gateway(Type='ipsec.1', PublicIp=public_ip)
            DoLog.info("<create_customer_gateway> response : %s", response)
            self._wait_till_customer_gateway_is_ready(response["CustomerGatewayId"])
            return response["CustomerGatewayId"]
        except Exception, fault:
            DoLog.traceback(fault)
            raise

    def create_vitual_private_gateway(self):
        '''
        Create Virtual Private Gateway
        '''
        try:
            ec2_client = self._get_ec2_client()
            response = ec2_client.create_vpn_gateway(Type='ipsec.1')
            DoLog.info("<create_vitual_private_gateway> response : %s", response)
            self._wait_till_virtual_private_gateway_is_ready(response["VpnGatewayId"])
            return response["VpnGatewayId"]
        except Exception, fault:
            DoLog.traceback(fault)
            raise

    def create_vpc_subnet(self, vpc_cidr_block, subnet_cidr_block):
        try:
            ec2_resource = _get_ec2_resource()
            ec2_client = _get_ec2_client()
            vpc = ec2_client.create_vpc(CidrBlock=vpc_cidr_block)
            subnet = ec2_resource.create_subnet(VpcId = vpc["VpcId"], CidrBlock=subnet_cidr_block)
            DoLog.info("<create_vpc_subnet> returning : vpc_id : %s, subnet_id: %s", vpc["VpcId"], subnet.id)
            return {vpc_id : vpc["VpcId"], vpc_ass_id : vpc["AssociationId"], subnet_id : subnet.id}
        except Exception, fault:
            DoLog.traceback(fault)
            raise

    def attach_virtual_private_gateway(self, vpn_gateway_id, vpc_id):
        try:
            ec2_client = _get_ec2_client()
            response = ec2_client.attach_internet_gateway(InternetGatewayId=vpn_gateway_id, VpcId=vpc_id)
        except Exception, fault:
            DoLog.traceback(fault)
            raise        

    def edit_vpc_route_table(self, vpc_id, vpn_gateway_id):
        try:
            ec2_resource = _get_ec2_resource()
            vpc_resource = ec2_resource.Vpc('id')
            route_table_iterator = vpc_resource.route_tables.all()
            for route_table in list(self.route_tables.all()):
                for association in list(route_table.associations.all()):
                    if association.main == True:
                        main_route_table.append(route_table)
            if len(main_route_table) != 1:
                raise Exception('cannot get main route table! {}'.format(main_route_table))
            main_route_table[0].create_route(GatewayId = vpn_gateway_id)
        except Exception, fault:
            DoLog.traceback(fault)
            raise

    def edit_security_group(self, vpc_id):
        try:
            ec2_resource = _get_ec2_resource()
            vpc_resource = ec2_resource.Vpc('id')
            sg_iterator = vpc.security_groups.all()
            default_security_group = self.get_default_security_group(self, sg_iterator)
        except Exception, fault:
            DoLog.traceback(fault)
            raise

    def create_vpn_connection(self, vpn_gateway_id, customer_gateway_id):
        try:
            ec2_client = _get_ec2_client()
            response = client.create_vpn_connection(Type='ipsec.1', CustomerGatewayId=customer_gateway_id, 
                                            VpnGatewayId=vpn_gateway_id, Options={'StaticRoutesOnly': True|False})

            DoLog.info("<create_vpn_connection> response : %s", response)
            return response["VpnConnectionId"]
        except Exception, fault:
            DoLog.traceback(fault)
            raise

    def get_default_security_group(self, sg_iterator):
        return default_security_group
        #some logic to fetch default security group.

    def _wait_till_virtual_private_gateway_is_ready(self, vpn_gateway_id):
        pass
        #some logic to check till gateway come from pending state to ready/working state

    def _wait_till_customer_gateway_is_ready(self, customer_gateway_id):
        pass
        #some logic to check till gateway come from pending state to ready/working state

    def get_instance_status(self, instance_ids):
        '''
        '''
        try:
            instance_status_details = {}
            if not len(instance_ids):
                DoLog.warn("<get_instance_status>: for emtpy list of instance_ids")
                return {}
            ec2_conn = self.connect_ec2()
            all_instance_status = ec2_conn.get_all_instance_status()
            for instance_details in all_instance_status:
                if instance_details.id in instance_ids:
                    DoLog.info("<get_instance_status> Instance ID : %s, Status: %s, Reachability: %s", 
                                                                                    instance_details.id, 
                                                                                    instance_details.instance_status.status,
                                                                                    instance_details.instance_status.details['reachability'])
                    instance_status = {}
                    instance_status[u'status'] = instance_details.instance_status.status
                    instance_status[u'reachability'] = instance_details.instance_status.details['reachability']
                    instance_status_details[instance_details.id] = instance_status

            for instance_id in instance_ids:
                if instance_id not in instance_status_details.keys():
                    DoLog.info("<get_instance_status> Instance (%s) is either stopped or terminated.", instance_id)
                    instance_status = {}
                    instance_status[u'status'] = "Stopped/Terminated"
                    instance_status[u'reachability'] = "Failed"
                    instance_status_details[instance_id] = instance_status

        except Exception, fault:
            DoLog.traceback(fault)
            DoLog.error("<get_instance_status> : Error while getting status.")
        finally:
            DoLog.debug("<get_instance_status> returning response: %s for instance_ids : %s", instance_status_details, instance_ids)
            return instance_status_details

    def start_ec2_instance(self, details, ami_id, subnet_id, security_group_id, private_ip, instance_type):
        '''
        Description : This api creates ec2 instance and retruns ec2 instance id
        '''
        try:
            ec2_conn = self.connect_ec2()
            DoLog.info("<start_ec2_instance> : launching ec2 instance with detail : %s", detail)

            interface = boto.ec2.networkinterface.NetworkInterfaceSpecification(subnet_id=subnet_id,
                                                                                groups=[security_group_id],
                                                                                associate_public_ip_address=False,
                                                                                private_ip_address = private_ip)

            interfaces = boto.ec2.networkinterface.NetworkInterfaceCollection(interface)
            reservation = ec2_conn.run_instances(image_id=ami_id, instance_type=instance_type, 
                                                                                network_interfaces=interfaces)

            instance = reservation.instances[0]

            try:
                while instance.update() != 'running':
                    time.sleep(5)
            except:
                pass

            instance_id = instance.id
            status_code = 0
            err_msg = None

            DoLog.info("<start_ec2_instance>: returning : %s", (instance_id, status_code, err_msg))
            return (instance_id, status_code, err_msg)
        except Exception, fault:
            DoLog.traceback(fault)
            raise fault  

    def get_ip_addresses(self, instance_id_list):
        response = {}
        for instance_id in instance_id_list:
            response[instance_id] = {}
        try:
            ec2_conn = self.connect_ec2()
            reservations = ec2_conn.get_all_instances(instance_ids=instance_id_list)
            for reservation in reservations:
                instance_id = reservation.instances[0].id
                try:
                    private_ip_address = reservation.instances[0].private_ip_address
                except:
                    private_ip_address = None
                try:
                    ip_address = reservation.instances[0].ip_address
                except:
                    ip_address = None
                response[instance_id]['public_ip'] = ip_address
                response[instance_id]['private_ip'] = private_ip_address
            DoLog.info("<get_ip_addresses> %s", response)
        except Exception, fault:
            DoLog.info("<get_ip_addresses>: Error while getting public ip and private ip for instance_ids : %s", instance_id_list)
            DoLog.traceback(fault)
        finally:
            return response
         
    def associate_elastic_ip(self, instance_id, elastic_ip):
        '''
        Description: associates elastic ip to instance given by instance_id.
        '''
        try:
            success = False
            ec2_conn = self.connect_ec2()
            addrs = ec2_conn.get_all_addresses()
            for addr in addrs:
                if addr.public_ip == elastic_ip:
                    if addr.instance_id == None and addr.allocation_id != None:
                        allocation_id = addr.allocation_id
                        success = ec2_conn.associate_address(instance_id, elastic_ip, allocation_id)
                        if success == True:
                            DoLog.info("<associate_elastic_ip> Successful for instance_id: %s where elastic_ip : %s", instance_id, elastic_ip)
                else:
                    continue
            if success == False:
                DoLog.warn("<associate_elastic_ip> Failed to associate elasticip for instance_id: %s for elastic_ip : %s", instance_id, elastic_ip)
        except Exception, fault:
            DoLog.traceback(fault)
        finally:
            return success

if __name__ == "__main__":
    '''
    Assume IM Role is properly assigned to instnace where this code is executed.
    '''

    '''
    Step 1 : Create VPN
    '''
    hybrio = ConnnectToDataCenter()
    customer_gateway_ip = "A.B.C.D"  #in your case Aviatrix Appliance IP
    customer_gateway_id =  hybrio.create_customer_gateway(customer_gateway_ip)
    vpn_gateway_id = hybrio.create_vitual_private_gateway()
    vpc_cidr_block = "10.0.0.0/16"
    subnet_cidr_block = "10.0.0.0/17"
    vpc_id, vpc_ass_id, subnet_id = hybrio.create_vpc_subnet(vpc_cidr_block, subnet_cidr_block)
    hybrio.attach_virtual_private_gateway(vpn_gateway_id, vpc_id)
    hybrio.edit_vpc_route_table(vpc_id, vpn_gateway_id)
    hybrio.edit_security_group(vpc_id)
    hybrio.create_vpn_connection(vpn_gateway_id, customer_gateway_id)

    '''
    Step 2 : Ready to use. You can launch instance in subnet with AMI availble with you.


    hybrio.start_ec2_instance
    hybrio.get_instance_status 
                        #untill intance is not running
    hybrio.associate_elastic_ip 
                        #if required
    hybrio.get_ip_addresses 
                        #if Auto-Assign private_ip is used
    hybrio.associate_instance_names 
                        #if you want to give name.

    '''