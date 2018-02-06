#!/usr/bin/env bash
 
################################################################
#   Bash Web Parameter Fuzzer
#   by Aung Khant, http://yehg.net
#   License: GPL v2  
#
#   takes 3 arguments:
#   one is a file with a list of fuzzable URLs (url like http://site.com/test.asp?s=str)
#   second is file with a list of payloads
#   third is file with regexp compatible pattern
#   
#   E.g If you send URL with "><script> which is included in 2nd argument file
#       you see "><script> in URL response, which is defined in 3nd argument file
#       then the url is likely vulnerable to xss and it's logged in urls.txt-vulnerable
#
#   Get payload files from http://yehg.net/lab/#words
#
#   Run an example so that you can get it better
#   fuzz-urls.txt payloads.txt response-patterns.txt
#   
#   sample contents of fuzz-urls.txt (line by line):
#   http://www.site.com/search.asp?txt=
#
#
#   sample contents of payloads.txt (line by line):
#   "><script>alert(/xss/)</script>
#   ' or 'a'='a
#
#
#   sample contents of response-pattern.txt (one line of regex):
#   ><script>|error|invalid
#
###################################################################
 
prog_name="\E[33mBash \E[32mWeb \E[31mParameter \E[34mFuzzer"
prog_ver=0.1-beta
prog_author="Aung Khant, aungkhant[at]yehg.net, http://yehg.net"
prog_author_co="YGN Ethical Hacker Group, Myanmar"
 
#url file
file_url=$1
#payload files
file_payreq=$2
file_payres=$3
vul_found=0
 
 
echo =================================================== 
echo 
echo -en $prog_name  $prog_ver
tput sgr0;echo;
echo by
echo $prog_author 
echo $prog_author_co 
echo 
echo =================================================== 
echo 
 
if [ $# -ne 3 ]; then
   echo Usage: ./$0 url-file req-file response-match-file 
   echo  
   echo e.g. ./$0 fuzz-urls.txt payload.txt payload-response-pattern.txt 
   echo 
 
   exit 
fi
 
if [ ! -e $1 ]; then
  echo URL file: file $1 does not exist 
  exit 
fi
if [ ! -e $2 ]; then
  echo Payload Request file: file $1 does not exist 
  exit 
fi
if [ ! -e $3 ]; then
  echo Payload Response Pattern file: file $1 does not exist 
  exit 
fi
 
 
echo -en[*] URL File to fuzz: "\E[33m$file_url" ; echo ; tput sgr0;
echo -en[*] Payload Request File: "\E[33m$file_payreq" ;echo ;tput sgr0;
echo -en[*] Payload Response Check File: "\E[33m$file_payres" ;echo ;tput sgr0;
echo 
sleep 2
echo [Start] `date` 
echo 
 
if [ -e $file_url-vulnerable ]; then
    rm $file_url-vulnerable 
fi
 
exec<$file_url
 
count=0
found_vuln_item=0
 
for line in $(cat $urlfile)
do
exec<$file_payreq
while read payload
do
        is_valid_url=`echo $line | grep -i -P ^http | wc -l`
        if [ $is_valid_url -eq 0 ]; then
          break 
        fi
        count=`expr $count + 1`
        echo 
        echo Request# $count
 
        has_param=`expr index "$line" "?"`
        if [ $has_param -ne 0 ]; then
                attack_url=${line//=/=$payload} ;
        else            
                attack_url=$line?$payload ;
        fi
 
        echo URL: $attack_url 
        rescode=`HEAD -s -d $line` 
        if [ `echo $rescode | grep -i -P 200 | wc -l ` -eq 1 ]; then
            echo -en Code: "\E[32m$rescode"; tput sgr0;
        fi
        if [ `echo $rescode | grep -i -P '40|50' | wc -l ` -eq 1 ]; then
            echo -en Code: "\E[31m$rescode"; tput sgr0;
        fi
        if [ `echo $rescode | grep -i -P 30 | wc -l ` -eq 1 ]; then
            echo -en Code: "\E[34m$rescode"; tput sgr0;
        fi
        echo 
 
        pgr=`cat $file_payres`
        url_res=`GET $attack_url`       
        echo Length: ${#url_res}
        check=`echo "$url_res" | grep -i -P $pgr | wc -l`
 
        if [ "$check" -ne 0 ]; then
                echo -en '\E[31m****This URL is vulnerable***' 
                tput sgr0
                echo $line >> $file_url-vulnerable 
                echo
                vul_found=1             
                found_vuln_item=`echo $found_vuln_item+1|bc`
        fi
        echo 
        echo vulnerable url\(s\) so far:  $found_vuln_item
        echo 
done
done
echo 
echo ___________________________________________;
echo 
echo "[*] Total Request(s): $count"
if [ $vul_found -eq 1 ]; then
   echo "[*] Vulnerable Url(s) Total:  $found_vuln_item"
   echo "[*] See Vulnerable URL(s) in $file_url-vulnerable"
fi 
echo 
echo [End] `date`
echo