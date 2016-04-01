# this solution is tested on Ubuntu 14.04 64bit LTS
# by Мухаммад Алифф Муаззам 
# ok i create this shell is because when i run this perl file, i got error like this.
: '

Can't locate Net/Pcap.pm in @INC (you may need to install the Net::Pcap module) (@INC contains: /etc/perl /usr/local/lib/perl/5.18.2 /usr/local/share/perl/5.18.2 /usr/lib/perl5 /usr/share/perl5 /usr/lib/perl/5.18 /usr/share/perl/5.18 /usr/local/lib/site_perl .) at ./whatsapp_discover.pl line 12.
BEGIN failed--compilation aborted at ./whatsapp_discover.pl line 12.

and

Can't locate NetPacket/Ethernet.pm in @INC (you may need to install the NetPacket::Ethernet module) (@INC contains: /etc/perl /usr/local/lib/perl/5.18.2 /usr/local/share/perl/5.18.2 /usr/lib/perl5 /usr/share/perl5 /usr/lib/perl/5.18 /usr/share/perl/5.18 /usr/local/lib/site_perl .) at ./whatsapp_discover.pl line 13.
BEGIN failed--compilation aborted at ./whatsapp_discover.pl line 13.

'
# so this is the solution.

echo "Downloading libnetpacket..."
wget http://launchpadlibrarian.net/158342276/libnetpacket-perl_1.4.4-1_all.deb
echo "Installing the packet..."
sudo dpkg -i libnetpacket-perl_1.4.4-1_all.deb
