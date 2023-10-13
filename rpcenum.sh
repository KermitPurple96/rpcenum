#!/bin/bash
 
# Author: Marcelo Vázquez (aka S4vitar)
# Added new features (kermit)
 
#Colours
greenColour="\e[0;32m\033[1m"
endColour="\033[0m\e[0m"
redColour="\e[0;31m\033[1m"
blueColour="\e[0;34m\033[1m"
yellowColour="\e[0;33m\033[1m"
purpleColour="\e[0;35m\033[1m"
turquoiseColour="\e[0;36m\033[1m"
grayColour="\e[0;37m\033[1m"
 
declare -r tmp_file="/dev/shm/tmp_file"
declare -r tmp_file2="/dev/shm/tmp_file2"
declare -r tmp_file3="/dev/shm/tmp_file3"
 
function ctrl_c(){
 
	echo -e "\n${yellowColour}[*]${endColour}${grayColour} Exiting...${endColour}"; sleep 1
	rm $tmp_file 2>/dev/null
	tput cnorm; exit 1
}
 
function helpPanel(){
 
	echo -e "\n${yellowColour}[*]${endColour}${grayColour} Uso: rpcenum${endColour}"
	echo -e "\n\t${purpleColour}e)${endColour}${yellowColour} Enumeration Mode${endColour}"
	echo -e "\n\t\t${grayColour}DUsers${endColour}${redColour} (Domain Users)${endColour}"
	echo -e "\t\t${grayColour}DUsersInfo${endColour}${redColour} (Domain Users with info)${endColour}"
	echo -e "\t\t${grayColour}DAUsers ${redColour}(Domain Admin Users)${endColour}"
	echo -e "\t\t${grayColour}DGroups ${redColour}(Domain Groups)${endColour}"
	echo -e "\t\t${grayColour}All ${redColour}(All Modes)${endColour}"
	echo -e "\n\t${purpleColour}i)${endColour}${yellowColour} Host IP Address${endColour}"
	echo -e "\n\t${purpleColour}u)${endColour}${yellowColour} Username${endColour}"
  echo -e "\n\t${purpleColour}p)${endColour}${yellowColour} Password${endColour}"
  echo -e "\n\t${purpleColour}d)${endColour}${yellowColour} Domain${endColour}"
  echo -e "\n\t${purpleColour}h)${endColour}${yellowColour} Show this help pannel${endColour}\n"
  echo -e "\n\t${redColour}Example: ${endColour}${yellowColour} rpcenum.sh -e All -i 192.168.1.1 -u 'Administrator' -p 'Password123' -d 'domain.local'${endColour}\n\n"
	exit 1
}
 
function printTable(){
 
    local -r delimiter="${1}"
    local -r data="$(removeEmptyLines "${2}")"
 
    if [[ "${delimiter}" != '' && "$(isEmptyString "${data}")" = 'false' ]]
    then
        local -r numberOfLines="$(wc -l <<< "${data}")"
 
        if [[ "${numberOfLines}" -gt '0' ]]
        then
            local table=''
            local i=1
 
            for ((i = 1; i <= "${numberOfLines}"; i = i + 1))
            do
                local line=''
                line="$(sed "${i}q;d" <<< "${data}")"
 
                local numberOfColumns='0'
                numberOfColumns="$(awk -F "${delimiter}" '{print NF}' <<< "${line}")"
 
                if [[ "${i}" -eq '1' ]]
                then
                    table="${table}$(printf '%s#+' "$(repeatString '#+' "${numberOfColumns}")")"
                fi
 
                table="${table}\n"
 
                local j=1
 
                for ((j = 1; j <= "${numberOfColumns}"; j = j + 1))
                do
                    table="${table}$(printf '#| %s' "$(cut -d "${delimiter}" -f "${j}" <<< "${line}")")"
                done
 
                table="${table}#|\n"
 
                if [[ "${i}" -eq '1' ]] || [[ "${numberOfLines}" -gt '1' && "${i}" -eq "${numberOfLines}" ]]
                then
                    table="${table}$(printf '%s#+' "$(repeatString '#+' "${numberOfColumns}")")"
                fi
            done
 
            if [[ "$(isEmptyString "${table}")" = 'false' ]]
            then
                echo -e "${table}" | column -s '#' -t | awk '/^\+/{gsub(" ", "-", $0)}1'
            fi
        fi
    fi
}
 
function removeEmptyLines(){
 
    local -r content="${1}"
    echo -e "${content}" | sed '/^\s*$/d'
}
 
function repeatString(){
 
    local -r string="${1}"
    local -r numberToRepeat="${2}"
 
    if [[ "${string}" != '' && "${numberToRepeat}" =~ ^[1-9][0-9]*$ ]]
    then
        local -r result="$(printf "%${numberToRepeat}s")"
        echo -e "${result// /${string}}"
    fi
}
 
function isEmptyString(){
 
    local -r string="${1}"
 
    if [[ "$(trimString "${string}")" = '' ]]
    then
        echo 'true' && return 0
    fi
 
    echo 'false' && return 1
}
 
function trimString(){
 
    local -r string="${1}"
    sed 's,^[[:blank:]]*,,' <<< "${string}" | sed 's,[[:blank:]]*$,,'
}
 
function extract_DUsers(){
 
	echo -e "\n${yellowColour}[*]${endColour}${grayColour} Enumerating Domain Users...${endColour}\n"
 
  if [ -n "$2" -a -n "$3" -a -n "$4" ]; then
	domain_users=$(rpcclient -U "$2\\$3%$4" $1 -c "enumdomusers" | grep -oP '\[.*?\]' | grep -v 0x | tr -d '[]')
  else
    domain_users=$(rpcclient -U "" $1 -c "enumdomusers" -N | grep -oP '\[.*?\]' | grep -v 0x | tr -d '[]')
  fi
 
	echo "Users" > $tmp_file && for user in $domain_users; do echo "$user" >> $tmp_file; done
 
	echo -ne "${blueColour}"; printTable ' ' "$(cat $tmp_file)"; echo -ne "${endColour}"
	rm $tmp_file 2>/dev/null
}
 
function extract_DUsers_Info(){
 
	extract_DUsers $1 $2 $3 $4 > /dev/null 2>&1
 
	echo -e "\n${yellowColour}[*]${endColour}${grayColour} Listing domain users with description...${endColour}\n"
 
  if [ -n "$2" -a -n "$3" -a -n "$4" ]; then
    for user in $domain_users; do
		 rpcclient -U "$2\\$3%$4" $1 -c "queryuser $user" | grep -v 'Time' | sed 's/\t//' | tr ':' ',' | sed 's/\t//' | tr -d ' ' >> $tmp_file
      username=$(cat $tmp_file | head -n 1 | awk '{print $2}' FS=",")
		 echo -e '\n' >> $tmp_file
      
      echo "User,$username" > $tmp_file2
  
      #cat $tmp_file
	   cat $tmp_file | sed '/^\s*$/d' | while read user_representation; do
		 if [ "$(echo $user_representation | awk '{print $2}' FS=',')" ]; then
			 echo "$(echo $user_representation | awk '{print $1}' FS=','),$(echo $user_representation | awk '{print $2}' FS=',')" >> $tmp_file2
		 fi
    
	 done
 
	 rm $tmp_file; mv $tmp_file2 $tmp_file
	 sleep 1; echo -ne "${blueColour}"; printTable ',' "$(cat $tmp_file)"; echo -ne "${endColour}"
	 rm $tmp_file 2>/dev/null
	 done


  else

    for user in $domain_users; do
		 rpcclient -U "" $1 -c "queryuser $user" -N | grep -v 'Time' | sed 's/\t//' | tr ':' ',' | sed 's/\t//' | tr -d ' ' >> $tmp_file
      username=$(cat $tmp_file | head -n 1 | awk '{print $1}' FS=",")
		 echo -e '\n' >> $tmp_file
      echo "Username,$username" > $tmp_file2
  
      #cat $tmp_file
	   cat $tmp_file | sed '/^\s*$/d' | while read user_representation; do
		 if [ "$(echo $user_representation | awk '{print $2}' FS=',')" ]; then
			 echo "$(echo $user_representation | awk '{print $1}' FS=','),$(echo $user_representation | awk '{print $2}' FS=',')" >> $tmp_file2
		 fi
    
	   done
 
	   rm $tmp_file; mv $tmp_file2 $tmp_file
	   sleep 1; echo -ne "${blueColour}"; printTable ',' "$(cat $tmp_file)"; echo -ne "${endColour}"
	   rm $tmp_file 2>/dev/null
	 done
  fi
 
}


function enum_shares(){
 
 
	echo -e "\n${yellowColour}[*]${endColour}${grayColour} Enumerating shared folders...${endColour}\n"
 
  if [ -n "$2" -a -n "$3" -a -n "$4" ]; then
		rpcclient -U "$2\\$3%$4" $1 -c "netshareenumall" | tr -d '\t' | sed 's/:/,/' | sed 's/\\/\\\\/g' >> $tmp_file
    lines=$(cat $tmp_file | wc -l)
    shares=$((lines / 4))
    
    for ((i = 1; i <= shares; i++)); do
      
      echo "$3,shares" > $tmp_file2
	   cat $tmp_file | sed '/^\s*$/d' | awk -v n=$i '/netname/ { if (++count == n) { print; getline; for (i=1; i<=3; i++) { print; getline } } }' >> $tmp_file2
      echo -e "\n" >> $tmp_file2
      
      cat $tmp_file2 | sed '/^\s*$/d' | while read user_representation; do
		   if [ "$(echo $user_representation | awk '{print $2}' FS=',')" ]; then
			   echo "$(echo $user_representation | awk '{print $1}' FS=','),$(echo $user_representation | awk '{print $2}' FS=',')" >> $tmp_file3
		   fi
      done
      
      echo "" > $tmp_file2;
	   sleep 1; echo -ne "${blueColour}"; printTable ',' "$(cat $tmp_file3)"; echo -ne "${endColour}"
	   echo "" > $tmp_file3;
      
    done
 
	 rm $tmp_file $tmp_file2 $tmp_file3 2>/dev/null


  else
    rpcclient -U "" $1 -c "netshareenumall" | tr -d '\t' | sed 's/:/,/' | sed 's/\\/\\\\/g' >> $tmp_file
    lines=$(cat $tmp_file | wc -l)
    shares=$((lines / 4))
    
    for ((i = 1; i <= shares; i++)); do
      
      echo "$3,shares" > $tmp_file2
	   cat $tmp_file | sed '/^\s*$/d' | awk -v n=$i '/netname/ { if (++count == n) { print; getline; for (i=1; i<=3; i++) { print; getline } } }' >> $tmp_file2
      echo -e "\n" >> $tmp_file2
      
      cat $tmp_file2 | sed '/^\s*$/d' | while read user_representation; do
		   if [ "$(echo $user_representation | awk '{print $2}' FS=',')" ]; then
			   echo "$(echo $user_representation | awk '{print $1}' FS=','),$(echo $user_representation | awk '{print $2}' FS=',')" >> $tmp_file3
		   fi
      done
      
      echo "" > $tmp_file2;
	   sleep 1; echo -ne "${blueColour}"; printTable ',' "$(cat $tmp_file3)"; echo -ne "${endColour}"
	   echo "" > $tmp_file3;
      
    done
 
	 rm $tmp_file $tmp_file2 $tmp_file3 2>/dev/null
  fi

}


function extract_DAUsers(){
 
	echo -e "\n${yellowColour}[*]${endColour}${grayColour} Enumerating Domain Admin Users...${endColour}\n"
 
  if [ -n "$2" -a -n "$3" -a -n "$4" ]; then
 
    rid_dagroup=$(rpcclient -U "$2\\$3%$4" $1 -c "enumdomgroups" | grep "Domain Admins" | awk 'NF{print $NF}' | grep -oP '\[.*?\]' | tr -d '[]')
 
	rid_dausers=$(rpcclient -U "$2\\$3%$4" $1 -c "querygroupmem $rid_dagroup" | awk '{print $1}' | grep -oP '\[.*?\]' | tr -d '[]')
 
    echo "DomainAdminUsers" > $tmp_file; for da_user_rid in $rid_dausers; do
 
		rpcclient -U "$2\\$3%$4" $1 -c "queryuser $da_user_rid" | grep 'User Name'| awk 'NF{print $NF}' >> $tmp_file
    done
 
  else
 
	rid_dagroup=$(rpcclient -U "" $1 -c "enumdomgroups" -N | grep "Domain Admins" | awk 'NF{print $NF}' | grep -oP '\[.*?\]' | tr -d '[]')
 
	rid_dausers=$(rpcclient -U "" $1 -c "querygroupmem $rid_dagroup" -N | awk '{print $1}' | grep -oP '\[.*?\]' | tr -d '[]')
 
	echo "DomainAdminUsers" > $tmp_file; for da_user_rid in $rid_dausers; do
		rpcclient -U "" $1 -c "queryuser $da_user_rid" -N | grep 'User Name'| awk 'NF{print $NF}' >> $tmp_file
	done
  fi
 
	echo -ne "${blueColour}"; printTable ' ' "$(cat $tmp_file)"; echo -ne "${endColour}"
	rm $tmp_file 2>/dev/null
}
 
function extract_DGroups(){
 
	echo -e "\n${yellowColour}[*]${endColour}${grayColour} Enumerating Domain Groups...${endColour}\n"
 
  if [ -n "$2" -a -n "$3" -a -n "$4" ]; then
 
    rpcclient -U "$2\\$3%$4" $host_ip -c "enumdomgroups" | grep -oP '\[.*?\]' | grep "0x" | tr -d '[]' >> $tmp_file
    echo "DomainGroup,Description" > $tmp_file2
	cat $tmp_file | while read rid_domain_groups; do
		rpcclient -U "$2\\$3%$4" $host_ip -c "querygroup $rid_domain_groups" | grep -E 'Group Name|Description' | sed 's/\t//' > $tmp_file3
		group_name=$(cat $tmp_file3 | grep "Group Name" | awk '{print $2}' FS=":")
		group_description=$(cat $tmp_file3 | grep "Description" | awk '{print $2}' FS=":")
		echo "$(echo $group_name),$(echo $group_description)" >> $tmp_file2
	done
 
  else
 
	rpcclient -U "" $host_ip -c "enumdomgroups" -N | grep -oP '\[.*?\]' | grep "0x" | tr -d '[]' >> $tmp_file
 
	echo "DomainGroup,Description" > $tmp_file2
	cat $tmp_file | while read rid_domain_groups; do
		rpcclient -U "" $host_ip -c "querygroup $rid_domain_groups" -N | grep -E 'Group Name|Description' | sed 's/\t//' > $tmp_file3
		group_name=$(cat $tmp_file3 | grep "Group Name" | awk '{print $2}' FS=":")
		group_description=$(cat $tmp_file3 | grep "Description" | awk '{print $2}' FS=":")
		echo "$(echo $group_name),$(echo $group_description)" >> $tmp_file2
	done
  fi
 
	rm $tmp_file $tmp_file3 2>/dev/null && mv $tmp_file2 $tmp_file
	echo -ne "${blueColour}"; printTable ',' "$(cat $tmp_file)"; echo -ne "${endColour}"
	rm $tmp_file 2>/dev/null
}
 
function extract_All(){
	extract_DUsers $1 $2 $3 $4
	extract_DUsers_Info $1 $2 $3 $4
	extract_DAUsers $1 $2 $3 $4
	extract_DGroups $1 $2 $3 $4
  enum_shares $1 $2 $3 $4
}
 
function beginEnumeration(){
 
	tput civis; nmap -p139 --open -T5 -v -n $host_ip | grep open > /dev/null 2>&1 && port_status=$?
 
  if [ -n "$domain" ] && [ -n "$user" ] && [ -n "$password" ]; then
	rpcclient -U "$domain\\$user%$password" $host_ip -c "enumdomusers" > /dev/null 2>&1
  else
    rpcclient -U "" $host_ip -c "enumdomusers" -N > /dev/null 2>&1
  fi
 
	if [ "$(echo $?)" == "0" ]; then
		if [ "$port_status" == "0" ]; then
			case $enum_mode in
				DUsers)
					extract_DUsers $host_ip $domain $user $password
					;;
				DUsersInfo)
					extract_DUsers_Info $host_ip $domain $user $password
					;;
				DAUsers)
					extract_DAUsers $host_ip $domain $user $password
					;;
				DGroups)
					extract_DGroups $host_ip $domain $user $password
					;;
				All)
					extract_All $host_ip $domain $user $password
					;;
				*)
					echo -e "\n${redColour}[!] Opción no válida${endColour}"
					helpPanel
          tput cnorm
					exit 1
					;;
			esac
		else
			echo -e "\n${redColour}Port 139 seems to be closed on $host_ip${endColour}"
			tput cnorm; exit 0
		fi
	else
		echo -e "\n${redColour}[!] Error: Access Denied${endColour}"
		tput cnorm; exit 0
	fi
}
 
# Main Function
 
if [ "$(echo $UID)" == "0" ]; then
	declare -i parameter_counter=0; while getopts ":e:i:u:p:d:h:" arg; do
		case $arg in
			e) enum_mode=$OPTARG; let parameter_counter+=1;;
			i) host_ip=$OPTARG; let parameter_counter+=1;;
      u) user=$OPTARG; let parameter_counter+=1;;
      p) password=$OPTARG; let parameter_counter+=1;;
      d) domain=$OPTARG; let parameter_counter+=1;;
			h) helpPanel;;
		esac
	done
 
	if [ $parameter_counter -lt 2 ]; then
		helpPanel
  #else if [ $parameter_counter -eq 2 ]; then
  #  anonEnumeration
  #  tput cnorm
	else
		beginEnumeration
		tput cnorm
	fi
else
	echo -e "\n${redColour}[*] It is necessary to run the program as root${endColour}\n"
fi
