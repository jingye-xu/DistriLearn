import json
import os


def var_read_json():
    if os.path.exists("./server_dist_variable.json"):
        with open("./server_dist_variable.json", "r", encoding="utf-8") as f:
            var = json.load(f)
            return var
    else:
        var = {
            "pfsense_wan_ip": "172.16.42.119",
            "pfsense_pass": "1",
            "pfsense_lan_ip": "192.168.1.1",
            "lan_nic": "vtnet1",
            "ssh_client_ip": "172.16.42.121",
            "ssh_client_port": "22",
            "dask_scheduler_ip": "192.168.0.41",
            "dask_scheduler_port": "8786",
        }

        with open("./server_dist_variable.json", 'w', encoding="utf-8") as f:
            json.dump(var, f, ensure_ascii=False, indent=4)

        return var


if __name__ == "__main__":
    var_read_json()
