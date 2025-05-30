## Uninstall and Install SSM Agent on RHEL 7

#### Remove agent
1. Log in with SSH.
2. Stop the agent:
sudo systemctl stop amazon-ssm-agent

3. Remove the agent:
sudo yum remove -y amazon-ssm-agent

4. Remove remaining files:
sudo rm -rf /var/lib/amazon/ssm
sudo rm -rf /etc/amazon/ssm
sudo rm -rf /var/log/amazon/ssm


#### Install agent
1. Create public key to verify package. Save to `amazon-ssm-agent.gpg`.
https://docs.aws.amazon.com/systems-manager/latest/userguide/verify-agent-signature.html

2. Import the public key to your key ring: 
sudo rpm --import amazon-ssm-agent.gpg

3. Install agent:
sudo yum install -y https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm

4. Verify agent is running:
sudo systemctl status amazon-ssm-agent