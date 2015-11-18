package Notifier::Handle;

use strict;
use warnings;

use Email::MIME;
use Email::Sender::Simple qw(sendmail);

use LWP::UserAgent;

use JSON;

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
        $self->addTask("Received incident report");

        if ($self->{config}->{mitigation}->{voxility}->{enable} && $self->{params}->{direction} eq 'incoming') {
            $self->mitigateVoxility($self->{config}->{mitigation}->{voxility});
        }

        if ($self->{config}->{annotation}->{enable} && $self->{params}->{action}) {
            $self->createAnnotation($self->{config}->{annotation});
        }

        if ($self->{config}->{notify}->{email}->{enable}) {
            $self->dispatchEmail($self->{config}->{notify}->{email});
        }

        if ($self->{config}->{notify}->{boxcar}->{enable}) {
            $self->dispatchBoxcar($self->{config}->{notify}->{boxcar});
        }

    } else {
        $self->addTask("Received unblock request");

        if ($self->{config}->{mitigation}->{voxility}->{enable} && $self->{params}->{direction} eq 'incoming') {
            $self->revertMitigationVoxility($self->{config}->{mitigation}->{voxility});
        }

        if ($self->{config}->{annotation}->{enable} && $self->{params}->{action}) {
            $self->createAnnotation($self->{config}->{annotation});
        }

        if ($self->{config}->{notify}->{email}->{enable}) {
            $self->dispatchEmail($self->{config}->{notify}->{email});
        }

        if ($self->{config}->{notify}->{boxcar}->{enable}) {
            $self->dispatchBoxcar($self->{config}->{notify}->{boxcar});
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

    my $server_endpoint = "http://$aconfig->{host}:$aconfig->{port}/$aconfig->{path}";
    
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

    my $server_endpoint = "https://$vconfig->{host}/$vconfig->{path}";

    $response = $ua->get($server_endpoint);

    if (!$response->is_success) {
        $self->addTask('Error while trying to get Voxility IP list');
        return;
    }

    my $status = Notifier::Helper::parseVoxilityList($response->content, $ip_address);

    Notifier::Helper::writeOldVoxilityStatus($ip_address, $status->{protected}, $self->{path});

    if ($status->{status} eq 1) {
        if ($status->{protected}) {
            $self->addTask("IP is in always on mode - Nothing to do");
        } else {
            $self->addTask("Protection triggered itself - Nothing to do")
        }
    } else {

        $self->addTask("Enabling Protection");

        my $post_data = {
            'mode' => "1;$status->{layer7}",
            'ip' => "${ip_address}/32",
            'passwordVOX' => $vconfig->{password},
            'submit' => "Save changes"
        };

        $response = $ua->post($server_endpoint, $post_data);

        if (!$response->is_success) {
            $self->addTask('Error while enabling DDoS Protection');
            return;
        }

        $response = $ua->get($server_endpoint);

        if (!$response->is_success) {
            $self->addTask('Error while trying to confirm that Protection is enabled');
            return;
        }

        $status = Notifier::Helper::parseVoxilityList($response->content, $ip_address);

        if ($status->{protected} == 1) {
            $self->addTask('Successfully enabled DDoS Protection');
        } else {
            $self->addTask('Failed to enable DDDoS Protection');
        }

    }

}

sub revertMitigationVoxility {
    my $self = shift;
    my $vconfig = shift;

    my $ip_address = $self->{params}->{ip_address};

    my $response;

    my $ua = LWP::UserAgent->new;

    my $server_endpoint = "https://$vconfig->{host}/$vconfig->{path}";

    my $oldstatus = Notifier::Helper::getOldVoxilityStatus($ip_address, $self->{path});

    if (!$oldstatus->{exists}) {
        $self->addTask("Protection is in old state - Nothing to do");
        return;
    }

    $response = $ua->get($server_endpoint);

    if (!$response->is_success) {
        $self->addTask('Error while trying to get Voxility IP list');
        return;
    }

    my $status = Notifier::Helper::parseVoxilityList($response->content, $ip_address);

    if ($status->{protected} eq $oldstatus->{status}) {
        $self->addTask("Protection is in old state - Nothing to do");
        return;    
    }

    $self->addTask("Setting back protection status to default");

    my $post_data = {
        'mode' => "$oldstatus->{status};$status->{layer7}",
        'ip' => "${ip_address}/32",
        'passwordVOX' => $vconfig->{password},
        'submit' => "Save changes"
    };

    $response = $ua->post($server_endpoint, $post_data);

    if (!$response->is_success) {
        $self->addTask('Error while enabling DDoS Protection');
        return;
    }

    $response = $ua->get($server_endpoint);

    if (!$response->is_success) {
        $self->addTask('Error while trying to get Voxility IP list');
        return;
    }

    $status = Notifier::Helper::parseVoxilityList($response->content, $ip_address);

    if ($status->{protected} == $oldstatus->{status}) {
        $self->addTask("Successfully changed protection back to old state ($oldstatus->{status})");
    } else {
        $self->addTask("Error while trying to change protection back to old state ($oldstatus->{status})");
    }

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