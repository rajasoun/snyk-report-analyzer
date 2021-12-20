#!/usr/bin/env bash

cookie=$(<cookie.txt) 
query=$(<query.txt) 

function urldecode() { 
  : "${*//+/ }"; echo -e "${_//%/\\x}"; 
}

function urlencode() {
  local string="${1}"
  local strlen=${#string}
  local encoded=""
  local pos c o

  for (( pos=0 ; pos<strlen ; pos++ )); do
     c=${string:$pos:1}
     case "$c" in
        [-_.~a-zA-Z0-9] ) o="${c}" ;;
        * )               printf -v o '%%%02x' "'$c"
     esac
     encoded+="${o}"
  done
  echo "${encoded}"    # You can either set a return variable (FASTER) 
}

function download_report(){
  echo "Download Report"
  curl -s 'https://app.snyk.io/org/cisco-lcande-pilot-ghe/reports/issues/export' \
    -H 'content-type: application/x-www-form-urlencoded' \
    -H 'accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9' \
    -H  "$cookie" \
    --data-raw "$query"\
    --compressed > issues.csv
  echo "Downloading Report Done !!!" 
}

function filter_log4j_vulnerabilities(){
  csv_file="issues.csv"
  lg4j_cve="CVE-2021-4104|CVE-2017-5645|CVE-2020-9488|CVE-2019-17571|CVE-2021-44228|CVE-2021-45046|CVE-2021-45046"
  headers="$(cat  $csv_file | head -1)"
  vuln_repos="$(grep -E $lg4j_cve $csv_file)"
  echo "$headers" > log4j_issues.csv
  echo "$vuln_repos" >> log4j_issues.csv
}

download_report
#filter_log4j_vulnerabilities
python3 analyze_snyk_report.py -f issues.csv
cat log4j_vulnerabilities.csv | tr -d '"' |  tr -d '[' | tr -d ']'> log4j_issues.csv
rm -fr issues.csv log4j_vulnerabilities.csv





