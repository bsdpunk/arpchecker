#!/usr/bin/perl
use Net::Pcap::Easy;
my @internalMac = qw( 0023329dcdf5 0023120914f9 );
# all arguments to new are optoinal
my $npe = Net::Pcap::Easy->new(
    dev              => "en0",
    packets_per_loop => 10,
    bytes_to_capture => 1024,
    timeout_in_ms    => 0, # 0ms means forever
    promiscuous      => 0, # true or false
    default_callback =>          sub {

        my ($npe, $ether, $po, $spo) = @_;

        if( $po ) {
            if( $po->isa("NetPacket::ARP") ) {                
                print "ARP packet: $po->{sha} -> $po->{tha}\n";
                my $element = $po->{sha};
                print $element;
                if (grep {$_ eq $element} @internalMac) {
                    print " ARP address is yours"."\n" ;
                }else{
                    print " intruder!\n";
                }
            }


        } 
    }
);
1 while $npe->loop;
