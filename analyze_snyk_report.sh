#!/usr/bin/env bash

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
  scope=$1
  org=$2
  url="https://app.snyk.io/org/$org/reports/issues/export"
  echo "Download Report"
  cookie=$(<config/cookie-$scope.txt) 
  query=$(<config/query-$scope.txt) 
  curl -s  $url \
    -H 'content-type: application/x-www-form-urlencoded' \
    -H 'accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9' \
    -H  "$cookie" \
    --data-raw "$query"\
    --compressed > /tmp/issues-$scope.csv
  echo "Downloading Report Done !!!" 
}

function filter_log4j_vulnerabilities(){
  csv_file="issues.csv"
  log4j_cve="CVE-2021-4104|CVE-2017-5645|CVE-2020-9488|CVE-2019-17571|CVE-2021-44228|CVE-2021-45046|CVE-2021-45046"
  headers="$(cat  $csv_file | head -1)"
  vuln_repos="$(grep -E $log4j_cve $csv_file)"
  echo "$headers" > log4j_issues.csv
  echo "$vuln_repos" >> log4j_issues.csv
}

download_report "www" "cisco-lcande-pilot-ghe"
download_report "wwwin" "cisco-lce-pilot"
cat /tmp/issues-www.csv <(echo) <(tail +2 /tmp/issues-wwwin.csv) > /tmp/issues.csv
echo -e "Merging Reports Done !!!"

#filter_log4j_vulnerabilities
python3 analyze_snyk_report.py -f /tmp/issues.csv
cat /tmp/log4j_vulnerabilities.csv | tr -d '"' |  tr -d '[' | tr -d ']' | rev | cut -c9- | rev > log4j_issues.csv






