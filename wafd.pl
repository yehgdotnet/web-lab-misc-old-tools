#!/usr/bin/perl -w
###############

use strict;

use Getopt::Std;
use Socket;

my $HAVE_SSL = 0;


# determine whether or not to enable SSL support
BEGIN {
    if (eval "require Net::SSLeay") {
        Net::SSLeay->import();
		Net::SSLeay::load_error_strings();
		Net::SSLeay::SSLeay_add_ssl_algorithms();
		Net::SSLeay::randomize(time());
		$HAVE_SSL = 1;
    }
}

my %options =  (
        TargetPort 	=> 80,
	HostPort 	=> 80,
        Mode 		=> "1.1"
);

my $VERSION = "0.1 beta";

my %args;
getopts("h:r:f:p:xv", \%args);

if (!$args{h}) {usage(); }

   print STDERR 
qq{ 
Web App Firewall Detector (wafd) v$VERSION
by d0ubl3_h3lix, http://yehg.net
Codes built upon put.pl by H.D. Moore <hdmoore\@digitaldefense.net>
Ref: Web Hacking Exposed 2nd Edition, ISBN:9780072262995

Host: $args{h}
};

$args{r} = "/";
$args{f} = "wafd.txt";

my $binip = gethostbyname($args{h});


if (length($binip) == 0)
{
   print STDERR "The host you specified is invalid.\n";
   exit(257);
} else {    
   $options{"ip"} = $binip;
   $options{"Target"} = $args{h};
   $options{"Host"} = $args{h};
}

if($args{x} && $HAVE_SSL == 0) { 
   print "Please install the Net::SSLeay module for SSL support.\n"; exit; 
}
if ($args{x}) { $options{"TargetPort"} = 443;}
if ($args{p}) { $options{"TargetPort"} = $args{p}; }

if ($args{v})
{
   print STDERR "\n[Options Table]\n";
   foreach my $key (keys(%options))
   {
      print STDERR "$key = " . $options{"$key"} . "\n";
   }
   print STDERR "\n\n";
}


my $data = "";
my $R = "";

if ($args{f})
{
	if(! -r $args{f})
	{ 
                open(OUT,">wafd.txt") || die "";
                print OUT "==== wafd test ====";
	}
	open (IN, "<".$args{f}) || die "failed to open local file: $!";
	while (<IN>){ $data .= $_; }
	close (IN);
	
	$R =
	"PUT /" . $args{f} . " HTTP/1.1\r\n" .        
	"Host: " . $args{h} . "\r\n" .
        "User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1) Gecko/20061010 Firefox/2.0\r\n" .
	"Content-Length: " . length($data) . "\r\n".
	"\r\n" . $data;	
}

my $results = send_request($R);
if ($args{v})
{
	print "\n[Response]\n$results\n\n";
}

if ($args{f})
{
      
	my @ar00 = split /\sServer: +/i,$results;	
	if ($ar00[1])	
	{
		my $sr = $ar00[1];	
		my @ssr = split /\r\n/i,$sr;
		my $sinfo = "";
		foreach(@ssr){s/"//g;$sinfo=$ssr[0];}
		print "Server  - ",$sinfo,"\n";
	}
        
	my @ar01 = split /\sX-Powered-By: +/i,$results;	
	if ($ar01[1])	
	{
		my $sr = $ar01[1];	
		my @ssr = split /\r\n/i,$sr;
		my $pinfo = "";
		foreach(@ssr){s/"//g;$pinfo=$ssr[0];}
		print "X-Powered-By  - ",$pinfo,"\n";
	}
 	my @ar02 = split /\sLast-Modified: +/i,$results;	
	if ($ar02[1])	
	{
		my $sr = $ar02[1];	
		my @ssr = split /\r\n/i,$sr;
		my $linfo = "";
		foreach(@ssr){s/"//g;s/\///;$linfo=$ssr[0];}
		print "Last-Modified  - ",$linfo,"\n";
	}       
        
        
# web application firewalls signatures

my %wafs_def = (
		"st8id"=>"TEROS",
		"ASINFO"=>"F5 Traffic Shield",
		"NCI__SessionId"=>"NetContinuum"
	);
my @wafs = keys %wafs_def;
	my $this_waf = "";	
	foreach(@wafs)
	{    
		if ($results =~ /$_=/)
		{
			$this_waf .= "\n- ".$wafs_def{"$_"};	
		}
	}
	if ($this_waf eq "")
	{
            my @ar0 = split /\sset-cookie: +/i,$results;	
            if ($ar0[1])	
            {
                    print "\n>>The target site may use firewall.\n";
                    
            }
            else
            {
		print "\n>>The target site may not use firewall.\n";
            }                 
	}
	else{print ">>The target site is using ",$this_waf," Web Application Firewall.\n";}
	my @ar0 = split /\sset-cookie: +/i,$results;	
	if ($ar0[1])	
	{
		my $sr = $ar0[1];	
		my @ssr = split /\r\n/i,$sr;
		my $cinfo = "";
		foreach(@ssr){s/"//g;$cinfo=$ssr[0];}
		print "\nCookie Info  - ",$cinfo,"\n";
	}

        
}


sub usage {
    print STDERR 
qq{ 
Web App Firewall Detector (wafd) v$VERSION
by Aung Khant, http://yehg.net
YGN Ethical Hacker Group, Myanmar
Codes built upon put.pl by H.D. Moore <hdmoore\@digitaldefense.net>
Ref: Web Hacking Exposed 2nd Edition, ISBN:9780072262995

Usage: $0 -h <host> 
	-h <host>       = host to fingerprint	
	-p <port>       = web server port [Optional. Default is 80]	

Other Options:
	-x              = ssl mode
	-v              = verbose
    
Example:
         $0 -h victim.com 
    	
};
    exit(1);
}

sub send_request {

   my ($request) = @_;
   my $results = "";
   my $got;
   my $ssl;
   my $ctx;
   my $res;

   if ($args{v})
   {
      print STDERR "[request]\n$request\n\n";    
   }

   select(STDOUT); $| = 1;
   socket(S,PF_INET,SOCK_STREAM, getprotobyname('tcp') || 0) || die("Socket problems: $!\n");
   select(S); $|=1;
   select(STDOUT);

   if(connect(S,pack "SnA4x8",2,$options{"HostPort"},$options{"ip"}))
   {
      if ($args{x})
      {
         $ctx = Net::SSLeay::CTX_new() or die_now("Failed to create SSL_CTX $!");
         $ssl = Net::SSLeay::new($ctx) or die_now("Failed to create SSL $!");
         Net::SSLeay::set_fd($ssl, fileno(S));   # Must use fileno
         $res = Net::SSLeay::connect($ssl);
         $res = Net::SSLeay::write($ssl, $request);  # Perl knows how long $msg is
         shutdown S, 1;    

         while ($got = Net::SSLeay::read($ssl))
         {
            $results .= $got;
         }         

         Net::SSLeay::free ($ssl);               # Tear down connection
         Net::SSLeay::CTX_free ($ctx);
         close(S); 
      } else {
         print S $request;
         sleep(1);
         shutdown S, 1; 
         while ($got = <S>) {
            $results .= $got;
         } 
         close(S);
      }
   } else { die("Error: connection failed.\n"); }
   return $results;
}

