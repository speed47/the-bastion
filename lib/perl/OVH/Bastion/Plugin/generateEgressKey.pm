package OVH::Bastion::Plugin::generateEgressKey;

# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use common::sense;

use File::Basename;
use lib dirname(__FILE__) . '/../../../../../lib/perl';
use OVH::Result;
use OVH::Bastion;
use OVH::Bastion::Plugin qw{ :DEFAULT };

sub help_algos {
    require Term::ANSIColor;
    my $fnret    = OVH::Bastion::get_supported_ssh_algorithms_list(way => 'egress');
    my @algoList = @{$fnret->value};
    my $algos    = Term::ANSIColor::colored(uc join(' ', @algoList), 'green');

    # when generating documentation, don't talk about "this" bastion, be generic
    if ($ENV{'PLUGIN_DOCGEN'}) {
        osh_info <<"EOF";
Note that the actually available algorithms on a bastion depend on the underlying OS and the configured policy.

A quick overview of the different algorithms::
EOF
    }
    else {
        osh_info <<"EOF";
With the policy and SSH version on this bastion,
the following algorithms are supported: $algos.

A quick overview of the different algorithms:
EOF
    }
    osh_info <<"EOF";

  +---------+------+----------+-------+-----------------------------------------+
  | algo    | size | strength | speed | compatibility                           |
  +=========+======+==========+=======+=========================================+
  | DSA     |  any | 0        | n/a   | obsolete, do not use                    |
  | RSA     | 2048 | **       | **    | works everywhere                        |
  | RSA     | 4096 | ***      | *     | works almost everywhere                 |
  | ECDSA   |  521 | ****     | ***** | OpenSSH 5.7+ (Debian 7+, Ubuntu 12.04+) |
  | Ed25519 |  256 | *****    | ***** | OpenSSH 6.5+ (Debian 8+, Ubuntu 14.04+) |
  +---------+------+----------+-------+-----------------------------------------+

This table is meant as a quick cheat-sheet, you're warmly advised to do
your own research, as other constraints may apply to your environment.
EOF
    return 0;
}

sub ask_passphrase {
    require Term::ReadKey;
    print "Please enter a passphrase for the private key that'll stay on the bastion (not echoed): ";
    Term::ReadKey::ReadMode('noecho');
    chomp(my $pass1 = <STDIN>);
    if (length($pass1) < 5) {

        # ssh-keygen will refuse
        print "\n";
        return R('ERR_PASSPHRASE_TOO_SHORT', msg => "Passphrase needs to be at least 5 chars");
    }
    print "\nPlease enter it again: ";
    chomp(my $pass2 = <STDIN>);
    print "\n";
    Term::ReadKey::ReadMode('restore');
    if ($pass1 ne $pass2) {
        return R('ERR_PASSPHRASE_MISMATCH', msg => "Passphrases don't match, please try again");
    }
    return R('OK', value => $pass1);
}

sub preconditions {
    my %params = @_;
    my $fnret;

    my            ($Self, $Group, $algo, $size, $Account, $context) =
      @params{qw{  Self  Group algo   size   Account   context}};

    if (!$algo || !$context || !$Self) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing argument algo[$algo] or context[$context] or Self[$Self]");
    }

    if (!grep { $context eq $_ } qw{ group account }) {
        return R('ERR_INVALID_PARAMETER', msg => "Type should be group or account");
    }

    # check whether algo is supported by system
    $fnret = OVH::Bastion::is_allowed_algo_and_size(algo => $algo, size => $size, way => 'egress');
    $fnret or return $fnret;
    ($algo, $size) = @{$fnret->value}{qw{ algo size }};    # untaint

    $fnret = $Self->check();
    $fnret or return $fnret;

    # check preconditions if we're generating a key for a group
    if ($context eq 'group') {
        if (!$Group || !$Self) {
            return R('ERR_MISSING_PARAMETER', msg => "Missing 'Group' or 'Self' parameter");
        }
        $fnret = $Group->check();
        $fnret or return $fnret;

        $fnret = $Group->hasOwner($Self, superowner => 1);
        if (!$fnret) {
            return R('ERR_NOT_GROUP_OWNER',
                msg =>
                  "Sorry, you're not an owner of group $Group, which is needed to manage its egress keys"
            );
        }

        return R(
            'OK',
            value => {
                Group      => $Group,
                algo       => $algo,
                size       => $size,
                context    => $context
            }
        );
    }
    elsif ($context eq 'account') {
        if (!$Account) {
            return R('ERR_MISSING_PARAMETER', msg => "Missing 'Account' parameter");
        }

        $fnret = $Account->check();
        $fnret or return $fnret;

        return R('OK', value => {Account => $Account, algo => $algo, size => $size, context => $context});
    }
    else {
        return R('ERR_INTERNAL');
    }
}

1;
