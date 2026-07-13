Display IP in taskbar
- [GitHub - NICKCHEESE/Kali-Toolbar-IP: My solution to adding IP addresses to Kali Linux toolbar (xfce) for maximum convenience](https://github.com/NICKCHEESE/Kali-Toolbar-IP)

API class setup
sudo apt install git docker-compose arjun golang-go
pip3 install mitmproxy2swagger termcolor cprint pycryptodomex requests

Install Burpsuite + jython + cert
Install burp extensions autorize

#Install Postman
cd /opt
sudo wget https://dl.pstmn.io/download/latest/linux64 -O postman-linux-x64.tar.gz && sudo tar -xvzf postman-linux-x64.tar.gz -C /opt && sudo ln -s /opt/Postman/Postman /usr/bin/postman

#Install JWT Tool
cd /opt
sudo git clone https://github.com/ticarpi/jwt_tool
cd jwt_tool
sudo chmod +x jwt_tool.py
sudo ln -s /opt/jwt_tool/jwt_tool.py /usr/bin/jwt_tool

#Install Kiterunner
cd /opt
sudo git clone  https://github.com/assetnote/kiterunner.git
cd kiterunner
sudo make build
sudo ln -s /opt/kiterunner/dist/kr /usr/bin/kr

Hacking-APIs (https://github.com/hAPI-hacker/Hacking-APIs)
https://github.com/hAPI-hacker/Hacking-APIs/tree/main/Wordlists
Some API/Bug Bounty tools
https://github.com/nahamsec/bbht
https://github.com/nahamsec/lazyrecon
https://github.com/maaaaz/webscreenshot

$ sudo wget -c https://github.com/danielmiessler/SecLists/archive/master.zip -O SecList.zip \
&& sudo unzip SecList.zip \
&& sudo rm -f SecList.zip

dl.pstmn.io
events.gw.postman.com
desktop.postman.com
analytics.getpostman.com
bifrost-https-v4.gw.postman.com
identity-api.getpostman.com
app.getpostman.com
bam.nr-data.net
events.launchdarkly.com
clientstream.launchdarkly.com
app.launchdarkly.com

cd /opt
sudo wget -c https://github.com/hAPI-hacker/Hacking-APIs/archive/refs/heads/main.zip -O HackingAPIs.zip \
sudo unzip HackingAPIs.zip \
sudo rm -f HackingAPIs.zip

#isntall Crapi
mkdir ~/lab 
cd ~/lab
sudo curl -o docker-compose.yml https://raw.githubusercontent.com/OWASP/crAPI/main/deploy/docker/docker-compose.yml
sudo docker-compose pull
sudo docker-compose -f docker-compose.yml --compatibility up -d



#isntall Vapi
cd ~/lab
sudo git clone https://github.com/roottusk/vapi.git
cd /vapi
sudo docker-compose up -d

sudo docker-compose ps