def lambda_handler(event, context):
    import requests
    import boto3
    from boto3.session import Session
    import os

    nacl_rule_number = 32701
    end_nacl_rule_number = 32710
    nacl_id = os.environ['nacl_id']

    ip_ranges = requests.get('https://ip-ranges.amazonaws.com/ip-ranges.json').json()
    ip_range_entries = ip_ranges['prefixes']

    # get S3 endpoint IPs
    update_nacl_entries = []
    for ip in ip_range_entries:
        if ip['service'] == 'S3' and ip['region'] == 'ap-northeast-1':
            update_nacl_entries.append(ip['ip_prefix'])
            update_nacl_count = len(update_nacl_entries)

    # get NACL entries
    client = boto3.client('ec2')
    nacl_list = client.describe_network_acls(NetworkAclIds=[nacl_id])['NetworkAcls'][0]['Entries']
    nacl_list_count = len(nacl_list)

    # update NACL
    for new_nacl_entry in update_nacl_entries:
        current_nacl_entry_count = 1
        for current_nacl_entry in nacl_list:
            if current_nacl_entry.get('RuleNumber') == nacl_rule_number:
                for direction in True,False:
                    # replace_network_acl_entry
                    response = client.replace_network_acl_entry(CidrBlock=new_nacl_entry,Egress=direction,NetworkAclId=nacl_id,Protocol='-1',RuleAction='allow',RuleNumber=nacl_rule_number)
                nacl_rule_number+=1
                break
            elif current_nacl_entry_count >= nacl_list_count:
                for direction in True,False:
                    # create_network_acl_entry
                    response = client.create_network_acl_entry(CidrBlock=new_nacl_entry,Egress=direction,NetworkAclId=nacl_id,Protocol='-1',RuleAction='allow',RuleNumber=nacl_rule_number)
                nacl_rule_number+=1
                break
            current_nacl_entry_count+=1

    # delete leftover NACL entries
    while nacl_rule_number <= end_nacl_rule_number:
        for current_nacl_entry in nacl_list:
            if current_nacl_entry.get('RuleNumber') == nacl_rule_number:
                for direction in True,False:
                    response = client.delete_network_acl_entry(Egress=direction,NetworkAclId=nacl_id,RuleNumber=nacl_rule_number)
                break
        nacl_rule_number+=1
