# this new api provides a solution when we cannot use uci after chroot ubuntu root partition
import subprocess
import datetime
import re
import time
import sys


attributes = ["src_ip", "src_mac", "src_port", "dest_port", "dest_ip"]


class BlackList:
    def __init__(self):
        self.src_ip = ""
        self.dest_ip = ""
        self.src_port = ""
        self.dest_port = ""
        self.src_mac = ""


def getBlackList(input: str=""):
    """
    this function directly interacts with the uci api and obtain current black list

    return: a dict contains black lists, key is the entry id
    """
    if len(input) == 0:
        result = subprocess.run(['ssh', 'root@127.0.0.1', 'uci show firewall'], capture_output=True, encoding='UTF-8')
        input = result.stdout
        
    rules = {}
    
    for line in input.splitlines():
        # find the entries contains rule
        if "@rule" in line:
            # parse the string line by line
            parsedline = re.split('[\[ \] . =]', line)

            # get entry id
            entry_id = parsedline[2]
            
            # find whether the id is added
            if entry_id in rules.keys():
                attribute = parsedline[4]
                
                # only cares the attribute in attributes
                if attribute in attributes:
                    # update value
                    setattr(rules[entry_id], attribute, parsedline[5])
            
            # not added before
            else:
                attribute = parsedline[4]
                
                # only cares the attribute in attributes
                if attribute in attributes:
                    
                    # add new key into the rules
                    newEntry = BlackList()
                    setattr(newEntry, attribute, parsedline[5])
                    rules[entry_id] = newEntry

    return rules


def findBlackList(blackList: dict, src_ip: str="", dest_ip: str="", src_port: str="", dest_port: str="", src_mac: str=""):
    """
    this function tries to find the target whether the black list entry exists

    return: -1 if not found, or an interget >= 0 f found
    """
    
    # dict is empty
    if not blackList:
        return -1

    # input validation check
    if max(len(src_ip), len(src_mac), len(src_port), len(dest_ip), len(dest_port)) == 0:
        print("invalid search. existing...")
        sys.exit(1)
    
    for key in blackList.keys():
        
        # check one by one
        # early exit
        if len(src_ip) > 0:
            if blackList[key].src_ip != src_ip:
                continue
            
        if len(src_port) > 0:
            if blackList[key].src_port != src_port:
                continue
            
        if len(src_mac) > 0:
            if  blackList[key].src_mac != src_mac:
                continue
            
        if len(dest_ip) > 0:
            if blackList[key].dest_ip != dest_ip:
                continue
            
        if len(dest_port) > 0:
            if blackList[key].dest_port != dest_port:
                continue
        
        # passed all checks
        return key
    
    # default return -1
    return -1


def addBlackList(src_ip: str="", dest_ip: str="", src_port: str="", dest_port: str="", src_mac: str="", aging_time: int=3600):
    """
    this function directly interacts with the uci api and add a new black list entry
    """
    
    # input validation check
    if max(len(src_ip), len(src_mac), len(src_port), len(dest_ip), len(dest_port)) == 0:
        print("invalid search. existing...")
        sys.exit(1)
    
    # calculate effective time
    start_date, start_time, stop_date, stop_time = getEffectiveTime(aging_time)
    
    # add rule and some prelimilary settings
    subprocess.run(['ssh', 'root@127.0.0.1', 'uci add firewall rule'], capture_output=True, encoding='UTF-8')
    subprocess.run(['ssh', 'root@127.0.0.1', 'uci set firewall.@rule[-1].dest="*"'], capture_output=True, encoding='UTF-8')
    subprocess.run(['ssh', 'root@127.0.0.1', 'uci set firewall.@rule[-1].target="REJECT"'], capture_output=True, encoding='UTF-8')
    
    # effective time range
    subprocess.run(['ssh', 'root@127.0.0.1', f'uci set firewall.@rule[-1].start_time="{start_time}"'], capture_output=True, encoding='UTF-8')
    subprocess.run(['ssh', 'root@127.0.0.1', f'uci set firewall.@rule[-1].stop_time="{stop_time}"'], capture_output=True, encoding='UTF-8')
    subprocess.run(['ssh', 'root@127.0.0.1', f'uci set firewall.@rule[-1].start_date="{start_date}"'], capture_output=True, encoding='UTF-8')
    subprocess.run(['ssh', 'root@127.0.0.1', f'uci set firewall.@rule[-1].stop_date="{stop_date}"'], capture_output=True, encoding='UTF-8')
    
    # check the 5 main attributes
    if len(src_ip) > 0:
        subprocess.run(['ssh', 'root@127.0.0.1', f'uci add_list firewall.@rule[-1].src_ip="{src_ip}"'], capture_output=True, encoding='UTF-8')
    if len(src_port) > 0:
        subprocess.run(['ssh', 'root@127.0.0.1', f'uci add_list firewall.@rule[-1].src_port="{src_port}"'], capture_output=True, encoding='UTF-8')
    if len(src_mac) > 0:
        subprocess.run(['ssh', 'root@127.0.0.1', f'uci add_list firewall.@rule[-1].src_mac="{src_mac}"'], capture_output=True, encoding='UTF-8')
    if len(dest_ip) > 0:
        subprocess.run(['ssh', 'root@127.0.0.1', f'uci add_list firewall.@rule[-1].dest_ip="{dest_ip}"'], capture_output=True, encoding='UTF-8')
    if len(dest_port) > 0:
        subprocess.run(['ssh', 'root@127.0.0.1', f'uci add_list firewall.@rule[-1].dest_port="{dest_port}"'], capture_output=True, encoding='UTF-8')
        
    applyFirewall()


def updateBlackList(entry_id: int=0, aging_time: int=3600):
    """
    this function directly interacts with the uci api and update an existing black list entry
    """
    
    # calculate effective time
    start_date, start_time, stop_date, stop_time = getEffectiveTime(aging_time)
    
    # update effective time range
    subprocess.run(['ssh', 'root@127.0.0.1', f'uci set firewall.@rule[{entry_id}].start_time="{start_time}"'], capture_output=True, encoding='UTF-8')
    subprocess.run(['ssh', 'root@127.0.0.1', f'uci set firewall.@rule[{entry_id}].stop_time="{stop_time}"'], capture_output=True, encoding='UTF-8')
    subprocess.run(['ssh', 'root@127.0.0.1', f'uci set firewall.@rule[{entry_id}].start_date="{start_date}"'], capture_output=True, encoding='UTF-8')
    subprocess.run(['ssh', 'root@127.0.0.1', f'uci set firewall.@rule[{entry_id}].stop_date="{stop_date}"'], capture_output=True, encoding='UTF-8')
    
    applyFirewall()


def blockHandler(src_ip: str="", dest_ip: str="", src_port: str="", dest_port: str="", src_mac: str="", aging_time: int=3600):

    # get existing black list
    existingBlackList = getBlackList()

    # search whether the required black entry exists
    result = findBlackList(existingBlackList, src_ip, dest_ip, src_port, dest_port, src_mac)

    # not found
    if result < 0:
        addBlackList(src_ip, dest_ip, src_port, dest_port, src_mac, aging_time)
    # found
    else:
        updateBlackList(result, aging_time)


def applyFirewall():
    """
    this functions should be called everytiem when the firewall is modified
    """
    subprocess.run(['ssh', 'root@127.0.0.1', 'uci commit firewall'], capture_output=True, encoding='UTF-8')
    subprocess.run(['ssh', 'root@127.0.0.1', '/etc/init.d/firewall reload'], capture_output=True, encoding='UTF-8')


def getEffectiveTime(aging_time: int=3600):
    """
    this function calculates the date and time for the black list
    """
    current_time = datetime.datetime.now()
    start_date = current_time.strftime("%Y-%m-%d")
    start_time = current_time.strftime("%H:%M:%S")
    
    effective_time = current_time + datetime.timedelta(seconds=aging_time)

    stop_date = effective_time.strftime("%Y-%m-%d")
    stop_time = effective_time.strftime("%H:%M:%S")

    return start_date, start_time, stop_date, stop_time


if __name__ == "__main__":
    print(getEffectiveTime())
    fakeoutput = """firewall.@defaults[0]=defaults
firewall.@defaults[0].input='ACCEPT'
firewall.@defaults[0].output='ACCEPT'
firewall.@defaults[0].synflood_protect='1'
firewall.@defaults[0].forward='ACCEPT'
firewall.@zone[0]=zone
firewall.@zone[0].name='lan'
firewall.@zone[0].input='ACCEPT'
firewall.@zone[0].output='ACCEPT'
firewall.@zone[0].forward='ACCEPT'
firewall.@zone[0].network='lan'
firewall.@zone[1]=zone
firewall.@zone[1].name='wan'
firewall.@zone[1].output='ACCEPT'
firewall.@zone[1].masq='1'
firewall.@zone[1].mtu_fix='1'
firewall.@zone[1].network='wan' 'wan6'
firewall.@zone[1].forward='ACCEPT'
firewall.@zone[1].input='REJECT'
firewall.@forwarding[0]=forwarding
firewall.@forwarding[0].src='lan'
firewall.@forwarding[0].dest='wan'
firewall.@rule[0]=rule
firewall.@rule[0].src_mac='00:00:00:11:11:11'
firewall.@rule[0].dest='*'
firewall.@rule[0].start_time='11:11:11'
firewall.@rule[0].stop_time='11:11:11'
firewall.@rule[0].start_date='2015-11-11'
firewall.@rule[0].stop_date='2025-11-11'
firewall.@rule[0].target='REJECT'
firewall.@rule[1]=rule
firewall.@rule[1].src_mac='00:22:11:11:22:11'
firewall.@rule[1].dest='*'
firewall.@rule[1].target='REJECT'
""" 

    # first time to add 
    blockHandler(src_mac="00:11:22:11:22:33")
    time.sleep(60)

    # the entry exists, update aging time
    blockHandler(src_mac="00:11:22:11:22:33")

    # add new
    blockHandler(src_mac="44:11:22:11:22:44")