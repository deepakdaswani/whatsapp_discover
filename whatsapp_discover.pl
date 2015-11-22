#!/usr/bin/perl

# WHATSAPP DISCOVER 1.1 
# Author: Deepak Daswani (@dipudaswani)
# Website: http://deepakdaswani.es
# Date: November, 2015

use Getopt::Long;
use Net::Pcap;
use NetPacket::Ethernet qw(:strip);
use NetPacket::IP;
use NetPacket::TCP;
use strict;

my ($pcap,$err,$dev,$help,$interface,@files);
my $count = 0;
my $file_count = 0;
my $hoffset = -1;

# Usage definition 

sub usage {

print "Unknown option: @_\n\n" if ( @_ );
print "\nWhatsapp Discover v1.1  --- Deepak Daswani (\@dipudaswani) 2015\n";
print "                            http://deepakdaswani.es \n";
print "Usage: whatsapp_discover -i interface | -f pcapfile[s]\n";
print "---------------------------------------------------------------\n\n\n";
exit;
}

# Parse command line arguments 

usage() if (@ARGV < 1 or ! GetOptions('help|?' => \$help, 'i=s' => \$interface, 'f=s{,}' => \@files) or defined $help);



if (!defined $interface && ! @files) { 
	print "Please select an option\n";
	usage();
}


if (defined $interface && @files) { 
	print "Please select either an interface or a [single|list of] pcap file[s]\n";
	usage();
}

# Print header
print "\nWhatsapp Discover v1.0  --- Deepak Daswani (\@dipudaswani) 2014\n";
print "                            http://deepakdaswani.es \n\n";

# Sniff or parse pcap file[s]

if (defined $interface) { sniff(); }
if (@files) { 
	foreach (@files) {
		print "Parsing $_ ...\n";
		parse_file($_);
		$file_count++;
	}
}

# Create pcap object from an interface (disabled in this PoC version)
sub sniff {
	print "\nReal time snifing was disabled in this initial version. \nSorry for the trouble\n\n";
	exit;
}

# Parse pcap files in batch. Creates pcap object from a saved file 
sub parse_file () {

	my $file = $_;
	$pcap = Net::Pcap::open_offline ("$file", \$err) or next;

	my $datalink;
	$datalink = Net::Pcap::datalink($pcap);
	# Fake a case block
	CASE: {
		# EN10MB capture files
		($datalink == 1) && do {
		$hoffset = 14;
		last CASE;
		};
			
		# Linux cooked socket capture files
		($datalink == 113) && do {
		$hoffset = 16;
		last CASE;
		};
			
		# DLT_IEEE802_11 capture files
		($datalink == 105) && do {
		$hoffset = 32;
		last CASE;
		}
	}


	my $filter = "tcp && (port 5222 or port 443 or port 5223)";  # Filters Whatsapp's traffic
	my $filter_t;
	Net::Pcap::compile( $pcap, \$filter_t, $filter, 1, 0 );
	Net::Pcap::setfilter( $pcap, $filter_t );
	Net::Pcap::loop( $pcap, 0, \&process_pkt, '' ); # Loop to process pcap file
	Net::Pcap::close($pcap); # Close pcap object 

}

# Function for printing a packet. Only for debug purposes 
sub print_pkt {
    my ($packet) = @_;   
my $i; 
    $i=0;
    while ($i < length($packet)) {
        print (substr($packet, $i, 4) . " ");
        $i = $i + 4;
        # mod 32 since we are dealing with ascii values, not hex values
        # (two characters instead of one byte)
        if (($i % 32) == 0) { print "\n"; };
    }
    print "\n\n";
} 



# Callback function that is applied to every packet processed in the loop
sub process_pkt {

	my ($data, $header, $packet) = @_;
	my $unpacket = unpack('H*', substr($packet, 0,1));
	if (($hoffset == 32) && ($unpacket == 88)) {
		$hoffset = 34;   # Add 2 bytes to the header is it is an IEEE 802.11 QOS frame
	}	

	my $paquete = substr($packet, $hoffset); # Hack to parse not only Ethernet but also IEEE 802.11 frames
	my $ip_obj  = NetPacket::IP->decode( $paquete );
	my $tcp_obj = NetPacket::TCP->decode( $ip_obj->{data} );
	
	if ($tcp_obj->{data} =~ /^WA.*?([a-zA-Z\-\.0-9]+).*?([0-9]{6,})/) {  # RegEx used to parse packet
		my $version = $1;
		my $telefono = $2;
		print "Got 1 number! S.O: $version Mobile number: +$telefono\n";
		$count++;
	} else  {  # For Android clients since ~ 2.11.476
		if ($tcp_obj->{data} =~ /^WA.*?([a-zA-Z\-\.0-9]+).*?privacy/) {  # RegEx used to parse packet
			my $version = $1;
			my $tcppacket = unpack('H*',$tcp_obj->{data});
			my $telefono = substr($tcppacket,136,11);     # Phone number is in hexadecimal 
 			print "Got 1 number! S.O: $version Mobile number: +$telefono\n";
			$count++;
		}
	}

}
print "\n$file_count files parsed. $count phone numbers using Whatsapp found...\n\n";
# End of file 
