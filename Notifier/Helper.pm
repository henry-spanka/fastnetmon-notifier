package Notifier::Helper;

use strict;
use warnings;

use Data::Validate::IP qw(is_ipv4);
use YAML::XS 'LoadFile';
use POSIX qw(strftime);

use JSON;

use Data::Dumper; # Debugging


my $FASTNETMON_PARAMS = {
    'Attack_type' => 1,
    'Attack_protocol' => 1,
    'Total_incoming_traffic' => 1,
    'Total_outgoing_traffic' => 1,
    'Total_incoming_pps' => 1,
    'Total_outgoing_pps' => 1,
    'Total_incoming_flows' => 1,
    'Total_outgoing_flows' => 1,
    'Initial_attack_power' => 1,

};

sub checkParams {
    my $params = shift;

    if (@ARGV != 4) {
        die "Usage:\nnotifier client_ip data_direction pps action\n";
    }

    checkIPv4OrFail($params->{ip_address});

    argumentFail("Invalid data direction", $params->{direction}) if ($params->{direction} !~ /^incoming|outgoing$/ );
    argumentFail("Invalid pps", $params->{pps}) if ($params->{pps} !~ /^-?\d+$/ );
    argumentFail("Invalid action", $params->{action}) if ($params->{action} !~ /^ban|unban|attack_details$/ );

}

sub checkIPv4OrFail {
    my $ipaddress = shift;

    if(!is_ipv4($ipaddress)) {
        # Not a valid IPv4!
        die "Not a valid IPv4 address!\nGot: ${ipaddress}\n";
    }
}

sub argumentFail {
    my $reason = shift;
    my $value = shift;

    die "Invalid param: ${reason}\nGot: ${value}\n";
}

sub getConfig {
    my $path = shift;

    return LoadFile("${path}/config.yaml");
}

sub parseSubject {
    my ($subject, $params) = @_;

    $subject =~ s/\$IP/$params->{ip_address}/g;
    $subject =~ s/\$DIRECTION/$params->{direction}/g;
    $subject =~ s/\$PPS/$params->{pps}/g;

    return $subject;
}

sub parseBody {
    my ($body, $params, $tasklog, $details) = @_;

    $body =~ s/\$IP/$params->{ip_address}/g;
    $body =~ s/\$DIRECTION/$params->{direction}/g;
    $body =~ s/\$PPS/$params->{pps}/g;

    $body =~ s/\$TASKLOG/${tasklog}/g;
    $body =~ s/\$RAW_DATA/$details->{raw}/g;

    foreach my $param (keys %{$details->{data}}) {
        $body =~ s/\$$param/$details->{data}->{$param}/g;
    }

    return $body;
}

sub getCurrentDate {
    return strftime('%d/%m/%Y %H:%M:%S', localtime);
}

sub getCurrentTimeForAnnotation {
    return strftime('%Y-%m-%dT%H:%M:%S.000Z', gmtime);
}

sub parseFastNetMonData {
    my $params = shift;
    my $path = shift;

    my $data = {};
    my $raw;

    my $line;

    my $key;
    my $value;

    my $filename = "${path}/cache/$params->{ip_address}.data";

    if (-f $filename && $params->{action} eq 'unban') {
        open (VFILE, $filename);
        while (<VFILE>) {
            chomp;

            $line = $_;

            if ($line =~ /^([A-Za-z0-9_.\s]+):\s([A-Za-z0-9_.\s]+)$/) {
                $key = $1;
                $value = $2;
                $key =~ s/\s+/_/g;
                chomp $key;

                if (defined($FASTNETMON_PARAMS->{$key})) {
                    $data->{$key} = $value;
                }
            }
            $raw .= "${line}\n";
        }
        close (VFILE);
        return { data => $data, raw => $raw };
    }

    open (VFILE, ">${filename}");

    foreach $line ( <STDIN> ) {
        chomp($line);

        if ($line =~ /^([A-Za-z0-9_.\s]+):\s([A-Za-z0-9_.\s]+)$/) {
            $key = $1;
            $value = $2;
            $key =~ s/\s+/_/g;
            chomp $key;

            if (defined($FASTNETMON_PARAMS->{$key})) {
                $data->{$key} = $value;
            }
        }
        $raw .= "${line}\n";
        print VFILE "${line}\n";

    }
    close (VFILE);

    return { data => $data, raw => $raw };
}

sub parseVoxilityList {
    my $ip = shift;
    my $object = shift;

    if (defined($object->{success}) && $object->{success}) {
        my $list = $object->{data}->{iplist};
        if (defined($list->{$ip}) && $list->{$ip}) {
            my $ipobject = $list->{$ip};
            return { protected => $ipobject->{mode}, status => $ipobject->{stat}, layer7 => $ipobject->{no_l7} ? 0 : 1, layer7_ssl => $ipobject->{no_ssl_l7} ? 0 : 1}; # negate Layer 7
        }
    }

    return { protected => 2, status => 2, layer7 => 1, layer7_ssl => 1};
}

sub getOldVoxilityStatus {
    my $ip = shift;
    my $path = shift;

    my $filename = "${path}/cache/${ip}.cache";

    return { exists => 0 } if (! -f $filename);

    open (VFILE, $filename);
    while (<VFILE>) {
        chomp;
        if ($_ =~ /^OLDSTATUS:\((\d)\|(\d)\|(\d)\)$/) {
            return { exists => 1, status => $1, l7 => $2, l7_ssl => $3 };
        }
    }
    close (VFILE);
}

sub writeOldVoxilityStatus {
    my $ip = shift;
    my $status = shift;
    my $l7 = shift;
    my $l7_ssl = shift;
    my $path = shift;

    my $filename = "${path}/cache/${ip}.cache";

    open (VFILE, ">${filename}");
    print VFILE "OLDSTATUS:(${status}|${l7}|${l7_ssl})";
    close (VFILE);
}

sub deleteOldVoxilityStatus {
    my $ip = shift;
    my $path = shift;

    unlink "${path}/cache/${ip}.cache";
}

sub trim {
    my $data = shift;

    $data =~ s/^\s+|\s+$//g if $data;

    return $data;
}

1;
