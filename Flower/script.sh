#!/bin/bash

# get the number of parameters
para_num=$#

# ip address for compute node 1 and node 2
node1=192.168.0.51
node2=192.168.0.52


# define help document
function helpcmd(){
    echo -e "--help \tShow this help document"
    echo ""
    echo -e "--eth\tSpecify the interface to collect packets, default is eth0"
    echo -e "--path\tSpecify the path to store files, default is /home/"
    echo -e "--file\tSpecify the filename to store packets, default is package.pcap"
    echo -e "--count\tSpecify the number of packets to collect, default is 10000"
    exit 0
}

# check if the number of input parameters is valid
if [ ${para_num} -eq 0 ]; then
    echo "No parameters are inputed."
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
    "--path")
        path=${para_list[i+1]}
        ;;
    "--file")
        filename=${para_list[i+1]}
        ;;
    "--count")
        count=${para_list[i+1]}
        ;;
    "--eth")
        eth=${para_list[i+1]}
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
if [ ! ${eth} ]; then
    echo "you missed the argument: --eth"
    echo "setting default values..."
    eth=eth0
    echo "interface is set to eth0"
fi

if [ ! ${path} ]; then
    echo "you missed the argument: --path"
    echo "setting default values..."
    path=/home/
    echo "path is set to /home/"
fi

if [ ! ${filename} ]; then
    echo "you missed the argument: --file"
    echo "setting default values..."
    filename=package.pcap
    echo "filename is set to package.pcap"
fi

if [ ! ${count} ]; then
    echo "you missed the argument: --count"
    echo "setting default values..."
    count=10000
    echo "count is set to 10000"
fi

while :
do
    # step 1 accumulate packages
    echo "Start monitor packages..."
    sudo tshark -w ${path}${filename} -i ${eth} -c ${count} -F pcap
    
    # wait 5min and stop tshark
    # sleep 10
    # ps -ef | grep tshark | grep -v grep | cut -c 9-15 | xargs sudo kill -9
    echo "Done"

    # step 2 filter and generate dataset
    echo "Start package analysis and filter"
    # parameter 1: path, parameter 2: prefix of file
    sudo python3 main.py ${path} ${filename%.pcap}
    echo "Done"
    
    # check file contents
    if [ `cat ${path}${filename%.pcap}_results_labeled_node1_processed.csv | wc -l` -gt 2 ]; then
        break
    fi
    echo "we need more packets to analyze"
    
done

# step 3 transfer dataset to nodes
echo "Distribute packages"
scp ${path}${filename%.pcap}_results_labeled_node1_processed.csv ubuntu@${node1}:./package_result_processed.csv
scp ${path}${filename%.pcap}_results_labeled_node2_processed.csv ubuntu@${node2}:./package_result_processed.csv
echo "Done"

# step 4 start server
echo "Open server"
python3 server.py &
echo "Done"

sleep 5

# step 5 start client
echo "Start slient"
ssh ubuntu@${node1} 'python3 ./client.py' &

sleep 1

ssh ubuntu@${node2} 'python3 ./client.py' &
echo "Done"
