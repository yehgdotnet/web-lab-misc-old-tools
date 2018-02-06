#!/usr/bin/perl -w

use strict;
use HTTP::Request::Common;
use LWP::UserAgent;
use Getopt::Std;
use URI::Escape;


my $ver = '0.1 beta';
my $logo = qq{
Web Server|Firewall Stress Tester $ver
(c) Aung Khant, http://yehg.net
YGN Ethical Hacker Group, Myanmar

Warning! Use it Only for ETHICAL PURPOSE!
Test for newly created OSS Web Proxies/Firewalls out there
'Coz I found vulnerability this way

};

my %args;
getopts("h:m:c:s:e:w", \%args);

if((!$args{s}) || (!$args{e}) )
{
	usage();
}

my $url = ($args{h})?$args{h}:'localhost';
my $method = ($args{m})?$args{m}:'post';
my $start = ($args{s})?$args{s}:1;
my $end = ($args{e})?$args{e}:512;
my $wait = ($args{w})?$args{w}:5;
my $payload = '';
my $payload_char = ($args{c})?$args{c}:'A';
my $req = '';
my $response = '';



my $ua = LWP::UserAgent->new();
$ua->timeout(10);

$ua->agent('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9) Gecko/2008052906 Firefox/3.0');
$ua->default_headers->push_header('Accept'=>'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8');	  
$ua->default_headers->push_header('Accept-Language'=>'en-us,en;q=0.5');
$ua->default_headers->push_header('Accept-Charset'=>'ISO-8859-1,utf-8;q=0.7,*;q=0.7');
$ua->default_headers->push_header('Cache-Control'=>'max-age=0');
$ua->default_headers->push_header('Content-length'=>0);
$ua->default_headers->push_header('Connection'=>'close');
$ua->timeout(60);


sub usage {
print $logo;
print 
qq{
Usage: $0 -h url -m method -c payload -s start -e end -w wait
	   
	   -h 
	      url to stress [default: localhost]
	   -m 
	      method - get or post or head [default: post]
	   -c 
	      payload character to send [default: A]
	   -s
	      start time to be sent
	      [Setting million/billion takes longer to process and eats your memory!]
	   -e
	      end time to be sent 
	      [Setting million/billion takes longer to process and eats your memory!]
	   -w
	      is a gap time in second between each request [default: 5 seconds]

Example:
       $0 -h yehg.net -m post -c \\\\0 -s 1 -e 512 -w 5	    
       $0 -h yehg.net:8080 -m post -c \\\\0 -s 1 -e 512 -w 5	    

Explanation:
       It'll send a flood of character \\0 to yehg.net starting from 1 till 512 times.
       You'll see at which time the target reponses strange/crushed.
	
};exit;}
print $logo;

#print "$url\n$method\nstart: $start\nend: $end\nwait: $wait\nchar:$payload_char\n";exit;

while(1)
{  
  $payload = $payload_char x $start; 
  $payload = uri_escape($payload); 
  if($method eq "get"){
	$req = GET "http://$url/?$payload";	
  }elsif ($method eq "post"){
	$req = POST "http://$url/",[ stress_test   => $payload];	
  }else {
	$req = HEAD "http://$url/$payload";	
  }
  $response = $ua->request($req);    
  if ($response->status_line =~ /(Can\'t connect to)/ ) {
     print "~ Proxy error? Can you netcat to $url?\n";exit;
  }   
  if($start<2){print "Sending $start","x";}else{print "Sending $start","x";}
  print "      ",$response->status_line,"\n";

  if ($response->status_line =~ /(closed connection)/ ) {
     print "\n~Server down at payload length: $start\n";exit;
  }   
  if ($end==$start){print "\n~Finished.\n";exit;}
  sleep $wait;
  $start=$start+1;
}
