package Notifier::Helper;

use strict;
use warnings;

use Data::Validate::IP qw(is_ipv4);
use YAML::XS 'LoadFile';
use POSIX qw(strftime);

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
    return LoadFile('../config.yaml');
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

    my $data = {};
    my $raw;

    my $line;

    my $key;
    my $value;

    my $filename = "../cache/$params->{ip_address}.data";

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
    my $raw = shift;
    my $ip = shift;

    if ($raw =~ /<td>${ip}\/32<\/td><td><font color=[A-Za-z0-9_.]+>[A-Za-z0-9_.]+\s\((\d)\)<\/font><\/td><td>(\d)<\/td><td><font color=[A-Za-z0-9_.]+>[A-Za-z0-9_.]+\s\((\d)\)<\/font>/) {
        return { protected => $1, status => $2, layer7 => $3};
    }

    return { protected => 2, status => 2, layer7 => 0};
}

sub getOldVoxilityStatus {
    my $ip = shift;

    my $filename = "../cache/${ip}.cache";

    return { exists => 0 } if (! -f $filename);

    open (VFILE, $filename);
    while (<VFILE>) {
        chomp;
        if ($_ =~ /^OLDSTATUS:(\d)$/) {
            return { exists => 1, status => $1 };
        }
    }
    close (VFILE);
}

sub writeOldVoxilityStatus {
    my $ip = shift;
    my $status = shift;

    my $filename = "../cache/${ip}.cache";

    open (VFILE, ">${filename}");
    print VFILE "OLDSTATUS:${status}";
    close (VFILE);
}

sub deleteOldVoxilityStatus {
    my $ip = shift;

    unlink "../cache/${ip}.cache";
}

1;
