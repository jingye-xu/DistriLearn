#!/bin/bash
#${target} valid value: ACCEPT REJECT DROP

#get the number of parameters
para_num=$#

#define help document
function helpcmd(){
    echo -e "--help  \tShow this help document"
    echo ""
    echo -e "--name  \tName of the firewall rule"
    echo -e "--protocol\tProtocol of the entry flow. Valid value: tcp udp icmp"
    echo -e "--src_ip\tsource ip address: X.X.X.X"
    echo -e "--dst_ip\tdestination ip address: X.X.X.X"
    echo -e "--target\tIt defines how to deal with this entry flow. Valid value: ACCEPT REJECT DROP"
    echo -e "--src_port\tSource port. Only needed when the protocol is tcp or udp"
    echo -e "--dst_port\tDestination port. Only needed when the protocol is tcp or udp"
}

#check if the number of input parameters is valid
if [ ${para_num} -eq 0 ]; then
    echo "please input necessary parameters"
    helpcmd
    exit 1
fi

if [ ${para_num} -eq 1 ] && [ $1 == "--help" ]; then
    helpcmd
    exit 0
fi

if [ `expr ${para_num} % 2` -ne 0 ]; then
    echo "parameter pairs are incomplete, check it!"
    exit 1
fi

#put parameters into a list
list_num=0
for para in $@;
do
    para_list[list_num]=$para
    list_num=`expr $list_num + 1`
done

#recognize parameters
i=0
while [ $i -lt ${para_num} ];
do
    case ${para_list[$i]} in
    "--name")
        name=${para_list[i+1]}
        ;;
    "--protocol")
        protocol=${para_list[i+1]}
        ;;
    "--src_ip")
        src_ip=${para_list[i+1]}
        ;;
    "--dst_ip")
        dst_ip=${para_list[i+1]}
        ;;
    "--target")
        target=${para_list[i+1]}
        ;;
    "--src_port")
        src_port=${para_list[i+1]}
        ;;
    "--dst_port")
        dst_port=${para_list[i+1]}
        ;;
    *)
        echo "wrong parameters: ${para_list[i]}"
        helpcmd
        exit 1
        ;;
    esac
    i=`expr $i + 2` 
done

#check completeness of parameters
if [ ! ${name} ]; then
    echo "you missed the argument: --name"
    exit 1
fi

if [ ! ${protocol} ]; then
    echo "you missed the argument: --protocol"
    exit 1
fi

if [ ! ${src_ip} ]; then
    echo "you missed the argument: --src_ip"
    exit 1
fi

if [ ! ${dst_ip} ]; then
    echo "you missed the argument: --dst_ip"
    exit 1
fi

if [ ! ${target} ]; then
    echo "you missed the argument: --target"
    exit 1
fi

if [ ${protocol} == "tcp" ]; then
    if [ ! ${src_port} ]; then
        echo "you should define --src_port if your protocol is tcp"
        exit 1
    elif [ ! ${dst_port} ]; then
        echo "you should define --dst_port if your protocol is tcp"
        exit 1
    fi
fi

if [ ${protocol} == "udp" ]; then
    if [ ! ${src_port} ]; then
        echo "you should define --src_port if your protocol is udp"
        exit 1
    elif [ ! ${dst_port} ]; then
        echo "you should define --dst_port if your protocol is udp"
        exit 1
    fi
fi

if [ ${protocol} == "icmp" ]; then
    if [ ${src_port} ] || [ ${dst_port} ]; then
        echo "you should NOT define --src_port or --dst_port if your protocol is icmp"
        exit 1
    fi
fi

function firewall_add(){
    id=`uci add firewall rule`
    uci add_list firewall.@rule[-1].proto=${protocol}
    uci set firewall.@rule[-1].name=${name}
    uci add_list firewall.@rule[-1].src_ip=${src_ip}
    uci set firewall.@rule[-1].dest='*'
    uci add_list firewall.@rule[-1].dest_ip=${dst_ip}
    uci set firewall.@rule[-1].target=${target}
    if [ ${protocol} == "tcp" ] || [ ${protocol} ==  "udp" ];then
        uci set firewall.@rule[-1].src_port=${src_port}
        uci set firewall.@rule[-1].dest_port=${dst_port}
    fi
    uci commit firewall
    /etc/init.d/firewall reload >> /dev/null 2>&1
    echo "${name} ${id}" >> rulename-id-table
}

firewall_add
