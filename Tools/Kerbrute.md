#kerbrute 
- [GitHub - ropnop/kerbrute: A tool to perform Kerberos pre-auth bruteforcing](https://github.com/ropnop/kerbrute)
- A tool to quickly bruteforce and enumerate valid Active Directory accounts through Kerberos Pre-Authentication
- Install kerbrute```
sudo git clone https://github.com/ropnop/kerbrute.git
cd kerbrute
sudo make all
sudo mv kerbrute_linux_amd64 /usr/local/bin/kerbrute
- `kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o valid_ad_users` enumerate users