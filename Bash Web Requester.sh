#!/usr/bin/env bash

################################################## ##############
# Bash Web Requester
# by Aung Khant, http://yehg.net
# License: GPL v2 
#
# takes 2 arguments:
# one is a file with a list of URLs (url like http://site.com/test.asp)
# second is file with regexp compatible pattern that checks page content for matched keywords
# 
# E.g If you request URL which contains string like 'require_once' in URL response, which is defined in 2nd argument file
# then the url is likely vulnerable to internal path disclosure
# 
# Run an example so that you can get it better
# req-urls.txt payload-res-pattern.txt
################################################## #################

prog_name="\E[33mBash \E[32mWeb \E[31mRequester"
prog_ver=0.1-beta
prog_author="Aung Khant, http://yehg.net"
prog_author_co="YGN Ethical Hacker Group, Myanmar"

#url file
file_url=$1
file_payres=$2
vul_found=0


echo =========================================== 
echo 
echo -en $prog_name $prog_ver
tput sgr0;echo;
echo by
echo $prog_author 
echo $prog_author_co 
echo 
echo =========================================== 
echo 

if [ $# -ne 2 ]; then
echo Usage: $0 url-file response-match-file 
echo 
echo e.g. $0 request-urls.txt response-check-pattern.txt 
echo 
exit 
fi

if [ ! -e $1 ]; then
echo URL file: file $1 does not exist 
exit 
fi

if [ ! -e $2 ]; then
echo Response Pattern file: file $1 does not exist 
exit 
fi

echo -en URL File to request: "\E[33m$file_url" ; echo ; tput sgr0;
echo -en Payload Response Check File: "\E[33m$file_payres" ;echo ;tput sgr0;
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
is_valid_url=`echo $line | grep -i -P ^http | wc -l`
if [ $is_valid_url -eq 0 ]; then
break
fi
count=`expr $count + 1`
echo 
echo Request# $count

attack_url=$line
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
check=`echo "$url_res" | grep -i -P "$pgr" | wc -l`

if [ "$check" -ne 0 ]; then
echo -en '\E[31m****This URL is vulnerable***' 
tput sgr0
echo $line >> $file_url-vulnerable
echo
vul_found=1
found_vuln_item=`echo $found_vuln_item+1|bc`

fi
echo 
echo vulnerable url\(s\) so far: $found_vuln_item
echo 
done
echo 
echo ___________________________________________;
echo 
echo " Total Request(s): $count"
if [ $vul_found -eq 1 ]; then
echo " Vulnerable Url(s) Total: $found_vuln_item"
echo " See Vulnerable URL(s) in $file_url-vulnerable"
fi
echo 
echo [End] `date`
echo