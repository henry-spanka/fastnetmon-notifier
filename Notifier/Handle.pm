package Notifier::Handle;

use strict;
use warnings;

use Email::MIME;
use Email::Sender::Simple qw(sendmail);

use LWP::UserAgent;

use JSON;

use Data::Dumper; # Debugging

sub new {
    my ($class, $params, $config, $path) = @_;

    my $details = Notifier::Helper::parseFastNetMonData($params, $path);

    return bless {
        params => $params,
        config => $config,
        tasks => [],
        details => $details,
        path => $path
    }, $class;
}

sub handle {
    my $self = shift;

    return if ($self->{params}->{action} eq 'attack_details'); # Not supported

    if ($self->{params}->{action} eq 'ban') {
        $self->addTask("Received network incident report");

        if ($self->{config}->{mitigation}->{voxility}->{enable}) {
            $self->mitigateVoxility($self->{config}->{mitigation}->{voxility});
        }

        $self->addTask("Finalyzing...");
        $self->addTask("All tasks completed - Dispatching Notifications");

        if ($self->{config}->{annotation}->{enable} && $self->{params}->{action}) {
            $self->createAnnotation($self->{config}->{annotation});
        }

        if ($self->{config}->{notify}->{slack}->{enable}) {
            $self->sendSlackMessage($self->{config}->{notify}->{slack});
        }

        if ($self->{config}->{notify}->{email}->{enable}) {
            $self->dispatchEmail($self->{config}->{notify}->{email});
        }

        if ($self->{config}->{notify}->{boxcar}->{enable}) {
            $self->dispatchBoxcar($self->{config}->{notify}->{boxcar});
        }

        if ($self->{config}->{notify}->{whmcs}->{enable}) {
            $self->sendWHMCSMessage($self->{config}->{notify}->{whmcs});
        }

    } else {
        $self->addTask("Received request to disable mitigation measures");

        if ($self->{config}->{mitigation}->{voxility}->{enable}) {
            $self->revertMitigationVoxility($self->{config}->{mitigation}->{voxility});
        }

        $self->addTask("Finalyzing...");
        $self->addTask("All tasks completed - Dispatching Notifications");

        if ($self->{config}->{annotation}->{enable} && $self->{params}->{action}) {
            $self->createAnnotation($self->{config}->{annotation});
        }

        if ($self->{config}->{notify}->{slack}->{enable}) {
            $self->sendSlackMessage($self->{config}->{notify}->{slack});
        }

        if ($self->{config}->{notify}->{email}->{enable}) {
            $self->dispatchEmail($self->{config}->{notify}->{email});
        }

        if ($self->{config}->{notify}->{boxcar}->{enable}) {
            $self->dispatchBoxcar($self->{config}->{notify}->{boxcar});
        }

        if ($self->{config}->{notify}->{whmcs}->{enable}) {
            $self->sendWHMCSMessage($self->{config}->{notify}->{whmcs});
        }
    }

}

sub dispatchEmail {
    my $self = shift;
    my $emailconfig = shift;

    my $message;

    my $action = $self->{params}->{action};

    my $subject = Notifier::Helper::parseSubject($emailconfig->{$action}->{subject}, $self->{params});

    my $bodytemp = Notifier::Helper::parseBody($emailconfig->{$action}->{body}, $self->{params}, $self->getTasksAsString(), $self->{details});

    my $body;

    for (split /^/, $bodytemp) {
        $body .= "$_ \r"; # Fix Outlook line breaks
    }

    foreach my $recipient (@{$emailconfig->{emailAddresses}}) {

        $message = Email::MIME->create(
          header_str => [
            From    => $emailconfig->{from},
            To      => $recipient,
            Subject => $subject,
          ],
          attributes => {
            encoding => 'quoted-printable',
            charset  => 'ISO-8859-1',
            content_type => 'text/plain'
          },
          body_str => $body,
        );

        sendmail($message);

    }
}

sub sendSlackMessage {
    my $self = shift;
    my $slackconfig = shift;

    my $action = $self->{params}->{action};
    my $params = $self->{params};

    my $subject = Notifier::Helper::parseSubject($slackconfig->{$action}->{subject}, $params);

    my $body = Notifier::Helper::parseBody($slackconfig->{$action}->{body}, $params, $self->getTasksAsString(), $self->{details});

    my $ua = LWP::UserAgent->new;

    my $date = `date +%Y%m%d`;
    chomp($date);

    my $post_data = {
        'token' => $slackconfig->{token},
        'text' => $subject,
        'attachments' => encode_json([
            {
                'color' => '#36a64f',
                'text' => Notifier::Helper::parseBody($slackconfig->{$action}->{attachment}, $params, $self->getTasksAsString(), $self->{details})
            }
        ]),
        'channel' => $slackconfig->{channel},
        'username' => $slackconfig->{username},
        'as_user' => 'false'
    };

    $ua->post("https://slack.com/api/chat.postMessage", $post_data);

    if ($slackconfig->{upload_report}) {
        my $post_data = {
            'token' => $slackconfig->{token},
            'content' => $body,
            'filetype' => 'text',
            'filename' => "$params->{ip_address}_$params->{direction}_$params->{action}_${date}.txt",
            'channels' => $slackconfig->{channel},
            'username' => $slackconfig->{username},
            'as_user' => 'false'
        };

        $ua->post("https://slack.com/api/files.upload", $post_data);
    }

}

sub sendWHMCSMessage {
    my $self = shift;
    my $whmcsconfig = shift;

    my $action = $self->{params}->{action};
    my $params = $self->{params};
    my $details = $self->{details}->{data};

    my $body = Notifier::Helper::parseBody($whmcsconfig->{$action}->{body}, $params, $self->getTasksAsString(), $self->{details});

    my $ua = LWP::UserAgent->new;

    my $post_data = {
        'token' => $whmcsconfig->{token},
        'ip' => $params->{ip_address},
        'direction' => $params->{direction},
        'attack_power' => $details->{Initial_attack_power},
        'attack_type' => $details->{Attack_type},
        'attack_protocol' => $details->{Attack_protocol},
        'tasklog' => $self->getTasksAsString(),
        'attack_details' => $body,
        'action' => $action
    };

    $ua->post($whmcsconfig->{url}, $post_data);
}

sub dispatchBoxcar {
    my $self = shift;
    my $boxcarconfig = shift;

    my $message;

    my $action = $self->{params}->{action};

    my $subject = Notifier::Helper::parseSubject($boxcarconfig->{$action}->{title}, $self->{params});

    my $body = Notifier::Helper::parseBody($boxcarconfig->{$action}->{description}, $self->{params}, $self->getTasksAsString(), $self->{details});

    foreach my $recipient (@{$boxcarconfig->{BoxcarAddresses}}) {

        $message = Email::MIME->create(
          header_str => [
            From    => $boxcarconfig->{from},
            To      => $recipient,
            Subject => $subject,
          ],
          attributes => {
            encoding => 'quoted-printable',
            charset  => 'ISO-8859-1',
            content_type => 'text/plain'
          },
          body_str => $body,
        );

        sendmail($message);

    }


}

sub createAnnotation {
    my $self = shift;
    my $aconfig = shift;

    my $params = $self->{params};

    my $action = $params->{action};

    my $ua = LWP::UserAgent->new;

    my $path = $aconfig->{$action}->{path};

    my $server_endpoint = "http://$aconfig->{host}:$aconfig->{port}/${path}";

    my $req = HTTP::Request->new(POST => $server_endpoint);

    $req->header('content-type' => 'application/json');

    my $bodytemp = Notifier::Helper::parseBody($aconfig->{$action}->{description}, $params, $self->getTasksAsString(), $self->{details});
    my $body;

    for (split /^/, $bodytemp) {
        $body .= "$_ <br>"; # Fix graphite annotation
    }

    my $post_data = {
        '@timestamp' => Notifier::Helper::getCurrentTimeForAnnotation(),
        'title' => Notifier::Helper::parseSubject($aconfig->{$action}->{title}, $params),
        'description' => $body,
        'tags' => "$params->{direction}, $params->{action}, $self->{details}->{data}->{Attack_type}, $self->{details}->{data}->{Attack_protocol}"
    };

    $req->content(encode_json($post_data));

    $ua->request($req);
}

sub mitigateVoxility {
    my $self = shift;
    my $vconfig = shift;

    my $ip_address = $self->{params}->{ip_address};

    my $response;

    my $ua = LWP::UserAgent->new;

    my $server_endpoint = "https://$vconfig->{host}/$vconfig->{endpoint}";
    $server_endpoint .= "?username=$vconfig->{username}&password=$vconfig->{password}";

    $self->addTask("Voxility mitigation enabled - Mitigating...");

    $self->addTask('Retrieving Voxility IP list');

    $response = $ua->get($server_endpoint."&action=list");

    if (!$response->is_success) {
        $self->addTask('Error while trying to get Voxility IP list');
        return;
    }

    my $object = decode_json(Notifier::Helper::trim($response->content));

    if (ref($object) ne 'HASH' || !%$object) {
        $self->addTask('Error while parsing Voxility IP List');
        return;
    }

    my $status = Notifier::Helper::parseVoxilityList($ip_address, $object);

    $self->addTask("Saving old Protection state to cache file");

    Notifier::Helper::writeOldVoxilityStatus($ip_address, $status->{protected}, $self->{path});

    if ($status->{status} eq 1) {
        if ($status->{protected} eq 1) {
            $self->addTask("Awesome! - IP is already in always on mode - Therefore we have nothing to do");
        } else {
            $self->addTask("Great! - Voxility's Sensor already detected the attack - Nothing to do");
        }
    } else {
        if ($status->{status} eq 2) {
            $self->addTask("Protection is in Sensor-Mode and Voxility did not detected the attack");
        } else {
            $self->addTask("Protection is disabled - Re-enabling it to mitigate");
        }

        $self->addTask("Enabling Voxility Protection");

        my $layer7_negated = $status->{layer7} ? 0 : 1; # negate Layer 7

        $response = $ua->get($server_endpoint."&ip=${ip_address}&mode=1&no_l7=${layer7_negated}");

        if (!$response->is_success || Notifier::Helper::trim($response->content) ne 'OK') {
            $self->addTask('Error while enabling DDoS Protection');
            return;
        }

        $self->addTask("Confirming, that the Voxility's DDoS protection is really enabled");

        $response = $ua->get($server_endpoint."&action=list");

        if (!$response->is_success) {
            $self->addTask('Error while trying to confirm that the Protection is enabled');
            return;
        }

        $object = decode_json(Notifier::Helper::trim($response->content));

        if (ref($object) ne 'HASH' || !%$object) {
            $self->addTask('Error while parsing Voxility IP List');
            return;
        }

        $status = Notifier::Helper::parseVoxilityList($ip_address, $object);

        if ($status->{protected} == 1) {
            $self->addTask('Awesome! - Protection is now enabled');
            $self->addTask('Attack mitigated successfully');
        } else {
            $self->addTask('Could not enable the DDoS Protection - Please check manually');
        }

    }

}

sub revertMitigationVoxility {
    my $self = shift;
    my $vconfig = shift;

    my $ip_address = $self->{params}->{ip_address};

    my $response;

    my $ua = LWP::UserAgent->new;

    my $server_endpoint = "https://$vconfig->{host}/$vconfig->{endpoint}";
    $server_endpoint .= "?username=$vconfig->{username}&password=$vconfig->{password}";;

    $self->addTask("Voxility mitigation enabled - Unblocking...");

    $self->addTask("Retrieving cached old Protection state");

    my $oldstatus = Notifier::Helper::getOldVoxilityStatus($ip_address, $self->{path});

    if (!$oldstatus->{exists}) {
        $self->addTask("No cached file found - Please check manually");
        return;
    }

    $self->addTask('Retrieving Voxility IP list');

    $response = $ua->get($server_endpoint."&action=list");

    if (!$response->is_success) {
        $self->addTask('Error while trying to get Voxility IP list');
        return;
    }

    my $object = decode_json(Notifier::Helper::trim($response->content));

    if (ref($object) ne 'HASH' || !%$object) {
        $self->addTask('Error while parsing Voxility IP List');
        return;
    }

    my $status = Notifier::Helper::parseVoxilityList($ip_address, $object);

    if ($status->{protected} eq $oldstatus->{status}) {
        $self->addTask("Great! - Protection is already in old state - Nothing to do");
        return;
    }

    $self->addTask("Changing Protection state back to old state ($oldstatus->{status})");

    my $layer7_negated = $status->{layer7} ? 0 : 1; # negate Layer 7

    $response = $ua->get($server_endpoint."&ip=${ip_address}&mode=$oldstatus->{status}&no_l7=${layer7_negated}");

    if (!$response->is_success || Notifier::Helper::trim($response->content) ne 'OK') {
        $self->addTask('Error while disabling DDoS Protection');
        return;
    }

    $self->addTask("Confirming, that Voxility's DDoS protection is really disabled");

    $response = $ua->get($server_endpoint."&action=list");

    if (!$response->is_success) {
        $self->addTask('Error while trying to get Voxility IP list');
        return;
    }

    $object = decode_json(Notifier::Helper::trim($response->content));

    if (ref($object) ne 'HASH' || !%$object) {
        $self->addTask('Error while parsing Voxility IP List');
        return;
    }

    $status = Notifier::Helper::parseVoxilityList($ip_address, $object);

    if ($status->{protected} == $oldstatus->{status}) {
        $self->addTask("Great! - Successfully changed protection back to old state ($oldstatus->{status})");
        $self->addTask("Mitigation measures disabled successfully");
    } else {
        $self->addTask("Error while trying to change protection back to old state ($oldstatus->{status})");
    }

    $self->addTask("Deleting cached protection status");

    Notifier::Helper::deleteOldVoxilityStatus($ip_address, $self->{path});

}

sub addTask {
    my ($self, $task) = @_;

    my $date = Notifier::Helper::getCurrentDate();

    my $message = "${date}: ${task}";

    push @{$self->{tasks}}, $message;

    print "${message}\n";
}

sub getTasksAsString {
    my $self = shift;

    my $res;

    foreach my $task (@{$self->{tasks}}) {
        $res .= "${task}\n";
    }

    return $res;
}

1;
