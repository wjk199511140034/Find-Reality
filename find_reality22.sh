#!/bin/bash
# 1.Prepare
deep_check=0
clean=0
has_ip=0
enable_scan=1
expend=0
bgp_tools=0
input_ip=""
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0"
LOCAL_DOMAINS=""
num_candidates=0
max_parallel=20
num_passed=0
PASSED_DOMAINS=".passed_domains.txt"
CHECK_RESULT="check_result.txt"
while [[ -e "$PASSED_DOMAINS" ]]; do
    PASSED_DOMAINS="${PASSED_DOMAINS%.*}(1).txt"
done
if ! touch "$PASSED_DOMAINS" 2>/dev/null; then
	echo "No permission to create file."
	echo "Please use sudo to execute script."
	exit 5
fi

usage() {
	echo "Usage: $0 [OPTIONS]"
	echo "Options:"
	echo "  -ip <ip_address>	Manually specify IP"
	echo "  -d, --deep_check	Enable deep check "
#	echo "  -b, --bgp_tools	Use bgp.tools get domains list."
	echo "  -l, --local_domains	Check local files"
	echo "  -e, --expend		Expend IP C-segments"
	echo "  -m, --multi_thread	multithreading, default is 20."
	echo "  -h, --help		Show this help message"
	exit 0
	}

while [[ "$#" -gt 0 ]]; do
	case $1 in
		-ip) input_ip="$2"; has_ip=1; shift 2;;
		-b|--bgp_tools) bgp_tools=1; shift 1;;
		-l|--local_domains) LOCAL_DOMAINS="$2"; enable_scan=0; shift 2;;
		-d|--deep_check) deep_check=1; shift 1;;
		-e|--expend) expend="$2"; shift 2;;
		-m|--multi_thread) max_parallel="$2"; shift 2;;
		-h|--help) usage ;;
		*) echo "Unknown option: $1" >&2
		 usage; exit 1 ;;
	esac
done

if [[ ! "$max_parallel" =~ ^[0-9]+$ ]]; then
	echo "Error: -m argument must be a number.."
	echo "Use -h to show help."
	exit 1
elif [[ "$max_parallel" -gt 80  ]]; then
	echo "Too many thread!">&2
	echo "You IP may banned by provider!">&2
	read -p "Are you sure? (y/n): " confirm < /dev/tty
	case "$confirm" in
		[yY]|[yY][eE][sS])
			;;
		*) 
			echo "Aborted by user." >&2
			exit 1 
		;;
	esac
fi

# 2.1 Fetch ip
if [ "$has_ip" -eq 1 ]; then
	if [[ ! "$input_ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
		echo "Error: -ip argument must input valid IPv4 address.">&2
		exit 1
	else
		ip_c_list=$(echo "$input_ip" | sed 's/\.[0-9]\{1,3\}$/.0/')
	fi
	echo "Using specified IP: $input_ip"
else
	input_ip=$(curl -s https://api.ipify.org)
	if [ -z "$input_ip" ]; then
		echo "Error: IP fetch failed.">&2
		echo "Use -ip to input manually.">&2
		exit 1
	else
		ip_c_list=$(echo "$input_ip" | sed 's/\.[0-9]\{1,3\}$/.0/')
		echo "Public IP: $input_ip">&2
	fi
fi
# 2.1 Build IP C list
if [[ ! "$expend" =~ ^[0-9]+$ ]]; then
	echo "Error: -e argument must be a number.">&2
	echo "Use -h to show help.">&2
	exit 1
elif [[ "$expend" -gt 0 && "$enable_scan" -eq 1 ]]; then
	echo "Expend $expend IP C-segments based on $input_ip.">&2
	if [[ "$expend" -gt 4 ]]; then
		echo "Too many IP need to scan!">&2
		read -p "Are you sure? (y/n): " confirm < /dev/tty
		case "$confirm" in
			[yY]|[yY][eE][sS])
				;;
			*) 
				echo "Aborted by user." >&2
				exit 1 
			;;
		esac
	fi
	IFS='.' read -r ip1 ip2 ip3 ip4 <<< "$ip_c_list"
	subnets=$(seq $((ip3 - expend / 2)) $((ip3 + (expend + 1) / 2)) | awk '$1>=0 && $1<=255')
	for s in $subnets; do
		ip_c_list="${ip_c_list}\n${ip1}.${ip2}.${s}.${ip4}"
	done
	ip_c_list=$(printf "%b" "$ip_c_list" | sort -u)
	echo "Total $(printf "%b" "$ip_c_list" | grep -c '\.') IP C-segments need to process.">&2
fi

# 3. Scan domains
scan_domains() {
	local target_ip=$1
	local domains=""
#	Use comman name quick scan
	local raw_ssl=$( timeout 3 openssl s_client -connect "${target_ip}:443" -alpn h2 </dev/null 2>&1 | tr -d '\0')
	if echo "$raw_ssl" | grep -qiE "Verif.*OK" && \
		echo "$raw_ssl" | grep -qi "TLSv1.3" && \
		echo "$raw_ssl" | grep -qi "X25519" && \
		echo "$raw_ssl" | grep -qi "ALPN protocol: h2"; then
		domains=$(echo "$raw_ssl" | grep -m1 -oP '(s:|subject:).*?CN\s*=\s*\K[^, \n/]+')
	else
		return
	fi
#	Deep scan 
	if [ "$deep_check" -eq 1 ]; then
		domains=$(echo -e "$domains\n$(echo "$raw_ssl" | openssl x509 -noout -subject -ext subjectAltName 2>/dev/null | grep -oP '(DNS:|CN\s*=\s*)\K[^, /]+')")
	fi
	domains=$(echo "$domains" | sed 's/^\*\.//' | sort -u | grep -v '^$')
	[[ -z "$domains" ]] && return
	# Delete the domain use CDN and not 200
	while read -r d; do
		local resolved_ip=$(getent ahosts "$d" 2>/dev/null | awk '{print $1}' | grep -v ":" | head -1)
		if [[ "$resolved_ip" != "${target_ip%.*}"* ]]; then
			continue
		fi
		local status_code=$(curl -4 -I -L -s -m 6 -A "$USER_AGENT" -o /dev/null -w "%{http_code}" "https://$d" 2>/dev/null)
		if [[ "$status_code" -eq 200 ]]; then
			echo "$d"
		fi
	done <<< "$domains"
}
export -f scan_domains
export deep_check
export PASSED_DOMAINS
if [ "$enable_scan" -eq 1 ]; then 
	printf "%b\n" "$ip_c_list" | while read -r this_ip_c; do
		if [[ -z "$this_ip_c" ]]; then
			continue
		fi
		echo "Scanning: ${this_ip_c}/24" >&2 
		for i in {0..28}; do
#			scan_domains "${this_ip_c%.*}.${i}" & 
			{ scan_domains "${this_ip_c%.*}.${i}"; printf "." >&2; } &
			while [[ $(jobs -p | wc -l) -ge $max_parallel ]]; do
				wait -n 2>/dev/null || sleep 0.1
			done
		done
		wait
		echo "" >&2
	done >> "$PASSED_DOMAINS"
	echo "Done!" >&2
fi

# 4. Check local files
check_local_domains() {
	local domains=$1
	local target_ip_c=$2
	local code=""
	local http_v=""
	local port=""
#	Exclude use CDN
	local resolved_ip=$(getent ahosts "$domains" 2>/dev/null | awk '{print $1}' | grep -v ":" | head -1)
#	if ! echo "$resolved_ip" | grep -q "^${target_ip_c%.*}\."; then
	if ! echo "$target_ip_c" | grep -q "^${resolved_ip%.*}."; then
		return
	fi
#	Get simple info
	local raw_text=$(curl --tlsv1.3 --http2 -4sIL -m 6 -A "$USER_AGENT" -o /dev/null \
		-w "%{http_code}|%{http_version}|%{remote_port}" "https://$domains" 2>/dev/null)
	IFS='|' read -r code http_v port <<< "$raw_text"
	if [[ "$code" != "200" ]] || \
		[[ "$http_v" != "2" ]]; then
		return
	fi
#	Check deep(x25519)
	if [[ "$deep_check" == 1 ]]; then
		local is_x25519=$(timeout 3 openssl s_client -connect "${domains}:$port" -tls1_3 -servername "$domains" </dev/null 2>&1 | grep -i "Server Temp Key: X25519")
		if [ -z "$is_x25519" ]; then
			return
		fi
	fi
	echo "$domains"
}
export -f check_local_domains
export deep_check
export USER_AGENT
if [ "$enable_scan" -eq 0 ]; then 
##	max_parallel=1 for debug
#	max_parallel=1
	if [[ ! -f "$LOCAL_DOMAINS" ]]; then
		echo "Error: specified file $LOCAL_DOMAINS not exist!">&2
	else
		echo  "Formatting $LOCAL_DOMAINS">&2
		domains_list=$(tr -s '[:blank:],;' '\n' < "$LOCAL_DOMAINS" | sed 's/^\*\.//' | grep -E '^[^.][^ ]*\.[^.]{2,}$' | sort -u)
		######delete this one when not debug
		domains_list=$(echo "$domains_list" | sed -n '128,355p')
		if [[ -n "$domains_list" ]]; then
			num_candidates=$(echo "$domains_list" | grep -c "")
			echo "Found $num_candidates candidates.">&2
#			input_ip=ip_c_list #enable expend for domains check model
			echo "Starting verification based on: $input_ip ">&2
			printf "%s\n" "$domains_list" | xargs -I {} -P "$max_parallel" \
				bash -c 'check_local_domains "$1" "$2"; echo -n "." >&2' -- {} "$input_ip" \
				>> "$PASSED_DOMAINS"
			echo -e "\nDone!">&2
		else
			echo "No valid domains found.">&2
		fi
	fi
fi

# 4.Save result
sort -u "$PASSED_DOMAINS" -o "$PASSED_DOMAINS" && sed -i '/^$/d' "$PASSED_DOMAINS"
if [ -s "$PASSED_DOMAINS" ]; then
    mv "$PASSED_DOMAINS" "$CHECK_RESULT"
	num_passed=$(grep -c '\.' "$CHECK_RESULT")
	echo "Found $num_passed passed domains.">&2
	echo "Check $CHECK_RESULT to see more details.">&2
else
    echo "No passed domains found." >&2
    rm -f "$PASSED_DOMAINS"
fi
