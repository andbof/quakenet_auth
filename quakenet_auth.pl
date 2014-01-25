#!/usr/bin/perl

use strict;
use warnings;
use vars qw($VERSION %IRSSI);

use Irssi;
use Digest::SHA;

$VERSION = '1.0';
%IRSSI = (
    authors => 'Andreas Bofjall',
    contact => 'andreas@gazonk.org',
    name => 'quakenet_auth',
    description => 'Provides automatic interaction with the Q challenge/response login "challengeauth"',
    license => 'GPLv2',
    changed => '2014-01-26',
);

my $CMD_NAME = 'quakenet_auth';     # Command to bind
my $TIMEOUT = 10;                   # Seconds until request is dropped if no response
my $Q_NICK = 'Q';
my $Q_ADDR = 'Q@CServe.quakenet.org';

# There is no reason to use anything other than the strongest algorithm
# available. As of this writing, that's SHA256.
my %ALGORITHM = (
    name => 'HMAC-SHA-256',
    hash => \&Digest::SHA::sha256_hex,
    hmac => \&Digest::SHA::hmac_sha256_hex,
);

my $PASS_LEN = 10;          # Quakenet limits passwords to 10 characters in this scheme
my $NOTICE_HANDLER = 'receive_notice';
my $NOTICE_SIGNAL = 'message irc notice';

# As the Q challenge API does not allow us to link challenges to requests,
# and the irssi API does not allow us to handle multiple copies of the
# same signal function in a sane way, we keep the state in the easiest way
# possible, i.e. in these variables. People shouldn't have multiple
# outstanding auth requests anyway.

my $user;
my $pass;
my $timeout_tag;

sub irc_lc {
    # IRC uses a somewhat different algorithm for converting character cases,
    # specified in section "2.2 Character codes" of RFC1459 "Internet Relay
    # Chat Protocol" (see http://tools.ietf.org/html/rfc1459.html).

    my ($s) = @_;
    $s =~ tr/\[\]\\/\{\}|/;

    return lc($s);
}

sub send_response {
    my ($server, $challenge) = @_;

    # This algorithm is described on https://www.quakenet.org/development/challengeauth

    my $trunc_pass = substr($pass, 0, $PASS_LEN);
    my $lower_user = irc_lc($user);
    my $key = $ALGORITHM{hash}->("${lower_user}:" . $ALGORITHM{hash}->($trunc_pass));

    my $response = $ALGORITHM{hmac}->($challenge, $key);

    $server->command("msg $Q_ADDR challengeauth $user $response $ALGORITHM{name}");
}

sub is_valid_quakenet_nick {
    my ($nick) = @_;

    # This list of valid characters is taken from
    # https://script.quakenet.org/wiki/Nick

    if ($nick =~ /[^0-9a-zA-Z\\\[\]^_\`\{|\}-]/) {
        return 0;
    } else {
        return 1;
    }
}

sub forget_everything {
    Irssi::timeout_remove($timeout_tag) if ($timeout_tag);
    Irssi::signal_remove($NOTICE_SIGNAL, $NOTICE_HANDLER);
    $timeout_tag = '';
    $user = '';
    $pass = '';
}

sub challenge_timed_out {
    if ($timeout_tag) {
        Irssi::print("Did not receive challenge from $Q_NICK within $TIMEOUT seconds");
        Irssi::print("Authentication timed out, perhaps $Q_NICK is down?");
    }

    forget_everything();
}

sub receive_notice {
    my ($server, $msg, $from, $address, $to) = @_;

    # This is just to be extra extra sure. IRC allows too many strange
    # characters in nicknames to sanitize them properly, but it's better
    # than nothing. Let's not trust the IRC servers more than necessary.
    if (!is_valid_quakenet_nick($from) || !is_valid_quakenet_nick($to)) {
        return;
    }

    # The Q challenge message does not contain many characters; we can
    # be more cautious here.
    if ($msg =~ /[^a-zA-Z0-9 -.]/) {
        return;
    }

    if ($from ne $Q_NICK || $to ne $server->{nick}) {
        # This was just a spurious notice, let's wait for the next one
        return;
    }

    if ($msg =~ /not available once you have authed/i) {
        forget_everything();
        Irssi::signal_stop();
        Irssi::print("$Q_NICK says you have already authed.");
        Irssi::print("Quakenet does not allow you to re-auth.");
        return;
    }

    if (!($msg =~ /challenge ([a-z0-9]+) ([a-z0-9 -]+)$/i)) {
        # This was just a spurious message from Q and not the challenge we
        # are waiting for, let's wait for the next notice
        return;
    }
    my $challenge = $1;
    my @hmacs = split(/ /, $2);

    if (!(grep { $_ eq $ALGORITHM{name} } @hmacs)) {
        forget_everything();
        Irssi::signal_stop();
        Irssi::print("Sorry, did not get $ALGORITHM{name} as one of the possible HMAC algorithms.");
        return;
    }

    send_response($server, $challenge);

    forget_everything();
    Irssi::signal_stop();
}

sub cmd_quakenet_auth {
    my ($data, $server, $witem) = @_;
    my (@params) = split(/ /, $data);

    if (scalar @params != 2) {
        Irssi::print("syntax: $CMD_NAME <user> <pass>");
        return;
    }

    if ($timeout_tag) {
        Irssi::print("There is already an outstanding auth challenge request.");
        Irssi::print("Please wait for it to finish or timeout.");
        return;
    }

    ($user, $pass) = split(/ /, $data);

    $timeout_tag = Irssi::timeout_add_once($TIMEOUT * 1000, \&challenge_timed_out, 0);
    Irssi::signal_add_first($NOTICE_SIGNAL, $NOTICE_HANDLER);

    Irssi::print("Requesting challenge from $Q_ADDR");
    $server->command("msg $Q_ADDR challenge");
}

Irssi::command_bind($CMD_NAME, 'cmd_quakenet_auth');
