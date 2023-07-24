import subprocess
import datetime

class BlackList:
    def __init__(self):
        self.src_ip = ""
        self.dest_ip = ""
        self.src_port = ""
        self.dest_port = ""
        self.src_mac = ""
        self.entry_id = 0


def getBlackList():
    """
    this function directly interacts with the uci api and obtain current black list

    return: a list contains black lists
    """
    pass


def findBlackList():
    """
    this function tries to find the target whether the black list entry exists

    return: -1 if not found, or an interget >= 0 f found
    """
    pass

def addBlackList(src_ip: str="", dest_ip: str="", src_port: str="", dest_port: str="", src_mac: str="", aging_time: int=3600):
    """
    this function directly interacts with the uci api and add a new black list entry
    """
    
    # input validation check
    if max(len(s)):
        return
    
    pass


def updateBlackList(entry_id: int=0, aging_time: int=3600):
    """
    this function directly interacts with the uci api and update an existing black list entry
    """
    pass


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