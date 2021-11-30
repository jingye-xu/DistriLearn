#!/bin/bash

#get the number of parameters
para_num=$#

#define help document
function helpcmd(){
    echo -e "--help  \tShow this help document"
    echo ""
    echo -e "--name  \tDefine which rule entry will be deleted"
}

#check if the number of input parameters is valid
if [ ${para_num} -eq 0 ]; then
    echo "please input parameter"
    helpcmd
    exit 1
fi

if [ ${para_num} -gt 2 ]; then
    echo "you should only input one parameter pair at one time"
    helpcmd
    exit 1
fi

case $1 in
    "--help")
        helpcmd
        exit 0
        ;;
    "--name")
        if [ ! $2 ]; then
            echo "you should designate the value of --name"
            exit 1
        fi
        name=$2
        ;;
    *)
        echo "wrong parameter, your input: $1"
        helpcmd
        exit 1
        ;;
esac
        
#find the corresponding id of name
data_line=`cat rulename-id-table | grep -w ${name}`

echo $data_line

name_pair=(${data_line})

if [ ! ${name_pair[0]} ]; then
    echo -e "cannot find the name: \"${name}\" in the file"
    exit 1
fi

if [ ${name_pair[2]} ]; then
    echo -e "found two or more matched results"
    exit 1
fi

function firewall_del(){
    uci del firewall.${name_pair[1]}
    uci commit firewall
    /etc/init.d/firewall reload >> /dev/null 2>&1
}

firewall_del

#delete the entry in rulename-id-table
delete_line=`grep -nw "${name}" rulename-id-table | cut -f1 -d:`
sed -i '${delete_line}d' rulename-id-table

