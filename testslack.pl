#!/usr/bin/perl

use strict;
use warnings;

use FindBin;
use lib $FindBin::Bin;

use Notifier::Helper;
use Notifier::Handle;

use File::Basename;

use Data::Dumper;

use WebService::Slack::IncomingWebHook;

use LWP::UserAgent;

my $params = {
    ip_address => $ARGV[0],
    'direction' => $ARGV[1],
    'pps' => $ARGV[2],
    'action' => $ARGV[3]
};

my $path = dirname(__FILE__);

my $config = Notifier::Helper::getConfig($path);

my $ua = LWP::UserAgent->new;

my $server_endpoint = "https://slack.com/api/files.upload";

my $post_data = {
    'token' => 'xoxb-26908929459-UUPGVwXUhI0TR9mGW3En0VEX',
    'content' => $body,
    'filetype' => 'text',
    'filename' => '$params->{ip_address}_$params->{direction}_$params->{action}.txt',
    'channels' => 'C0SU3B082'
};

my $response = $ua->post($server_endpoint, $post_data);

print Dumper($response);
