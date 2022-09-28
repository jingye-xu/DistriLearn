# Configure Pi running the wireless AP (Access Point) mode.  

Note from Gabriel: Some of the best results tend to be by saving and applying each of the settings you change in lock-step, instead of all at once. (At least for me that's true).

## 1  Flash image on your Pi device  
  1.1 Download images from [OpenWrt official Pi project](https://openwrt.org/toh/raspberry_pi_foundation/raspberry_pi)  
  1.2 Follow the instructions to flash images. Please note that Pi3 B+ needs additional preparation. Otherwise, the wireless may not work properly. [Click here](https://openwrt.org/toh/raspberry_pi_foundation/raspberry_pi#wireless_country_code_issue)  

## 2  First time login OpenWrt web GUI - LuCI  
  2.1 If it is your first time to connect the Pi, the Ethernet port is running as the LAN port and providing DHCP service by default. 
Use a network cable connect your pc to the Pi's Etherent port to get an ip address (the ip address shoule be in 192.168.1.0/24).  
  2.2 Once get a valid ip address, open a broswer and type Pi's ip address (192.168.1.1 by default).  
  2.3 Input any password to login, and then navigate `System-Administration-Router Password` to set the login password.  

## 3 Change Pi into wireless AP mode
### 3.1 Interfaces Configuration  
Path: `Network-Interfaces`  

Overview:  
![interface overview](interface_overview.png)  

Click on edit:  
![interface_conf1](interface_conf1.png)  
![interface_conf2](interface_conf2.png)  

### 3.2 Wireless Configuration
Path: `Network-Wireless`  

Overview:  
![wireless_overview](wireless_overview.png)  
Please note that you may need to enable the wireless network first.  * If something goes wrong on the first try, you may have to enable it first.

Basic configuration:  
![wireless_conf1](wireless_conf1.png)  

Wireless password:  
![wireless_conf1](wireless_conf2.png)  

### 3.3 Firewall
Path: `Network-Firewall`  

Change all the `reject` to `accept`, we will configure our firewall rules later, here we allow all the traffices:  
![firewall_overview](firewall_overview.png)  

### 3.4 Once all the configuration is done, click on the `Save & Apply`  
