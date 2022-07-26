package OVH::Bastion::Plugin::generatePassword;

# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use common::sense;

use File::Basename;
use lib dirname(__FILE__) . '/../../../../../lib/perl';
use OVH::Result;
use OVH::Bastion;

sub preconditions {
    my %p = @_;
    my $fnret = OVH::Bastion::check_args(\%p,
        mandatory => [qw{ Self size context }],
        optionalFalseOk => [qw{ group account sudo }],
    );
    $fnret or return $fnret;

    my ($group, $shortGroup, $passhome, $base, $Account);

    if ($p{'context'} eq 'group') {
        if (not $p{'group'}) {
            return R('ERR_MISSING_PARAMETER', msg => "Missing argument 'group'");
        }
        $fnret = OVH::Bastion::is_valid_group_and_existing(group => $p{'group'}, groupType => 'key');
        $fnret or return $fnret;
        $group      = $fnret->value->{'group'};
        $shortGroup = $fnret->value->{'shortGroup'};
        $passhome   = "/home/$group/pass";
        $base       = "$passhome/$shortGroup";
    }
    elsif ($p{'context'} eq 'account') {
        if (not $p{'account'}) {
            return R('ERR_MISSING_PARAMETER', msg => "Missing argument 'account'");
        }
        $Account = OVH::Bastion::Account->newFromName($p{'account'}, check => 1);
        $Account or return $Account;
        $passhome = $Account->passHome;
        $base     = "$passhome/".$Account->sysUser;
    }
    else {
        return R('ERR_INVALID_PARAMETER', msg => "Expected a context 'group' or 'account'");
    }

    my $Self = $p{'Self'};
    $fnret = $Self->selfCheck();
    $fnret or return $fnret;

    return R('ERR_INVALID_PARAMETER', msg => "The argument 'size' must be an integer") if $p{'size'} !~ /^\d+$/;
    return R('ERR_INVALID_PARAMETER', msg => "Specified size must be >= 8")            if $p{'size'} < 8;
    return R('ERR_INVALID_PARAMETER', msg => "Specified size must be <= 127")          if $p{'size'} > 128;

    if ($p{'context'} eq 'account' && $Self ne $Account) {
        $fnret = OVH::Bastion::is_user_in_group(user => $Self->sysUser, group => "osh-accountGeneratePassword");
        $fnret or return R('ERR_SECURITY_VIOLATION', msg => "You're not allowed to run this, dear $Self");
    }
    elsif ($p{'context'} eq 'group') {
        $fnret = OVH::Bastion::is_group_owner(account => $Self->sysUser, group => $shortGroup, superowner => 1, sudo => $p{'sudo'});
        $fnret or return R('ERR_NOT_ALLOWED', msg => "You're not a group owner of $shortGroup, dear $Self");
    }

    # return untainted values
    return R(
        'OK',
        value => {
            Self       => $Self,
            Account    => $Account,
            shortGroup => $shortGroup,
            group      => $group,
            size       => $p{'size'},
            context    => $p{'context'},
            base       => $base,
            passhome   => $passhome,
        }
    );
}

sub act {
    my %params = @_;
    my $fnret  = preconditions(%params);
    $fnret or return $fnret;

    my %values = %{$fnret->value()};
    my          ( $Self,$Account,$shortGroup,$group,$size,$context,$passhome,$base) =
      @values{qw{  Self  Account  shortGroup  group  size  context  passhome  base }};

    my $pass;
    my $antiloop = 1000;

    my $hashes;
  RETRY: while ($antiloop-- > 0) {

        # generate a password
        $pass = '';
        foreach (1 .. $size) {
            $pass .= chr(int(rand(ord('~') - ord('!')) + ord('!')));
        }

        # get the corresponding hashes
        $fnret = OVH::Bastion::get_hashes_from_password(password => $pass);
        $fnret or return $fnret;

        # verify that the hashes match this regex (some constructors need it)
        my $check_re = qr'^\$\d\$[a-zA-Z0-9]+\$[a-zA-Z0-9.\/]+$';
        foreach my $hash (keys %{$fnret->value}) {
            next RETRY if ($fnret->value->{$hash} && $fnret->value->{$hash} !~ $check_re);
        }

        $hashes = $fnret->value;
        last;
    }

    if (ref $hashes ne 'HASH') {
        return R('ERR_INTERNAL', msg => "Couldn't generate a valid password");
    }

    # push password in a file
    if (!-d $passhome) {
        if (!mkdir $passhome) {
            return R('ERR_INTERNAL', msg => "Couldn't create passwords directory in group home '$passhome' ($!)");
        }
        if ($context eq 'account') {
            chown $Account->uid, $Account->gid, $passhome;
        }
    }
    if (!-d $passhome) {
        return R('ERR_INTERNAL', msg => "Couldn't create passwords directory in group home");
    }
    chmod 0750, $passhome;
    if (-e $base) {

        # rotate old passwords
        unlink "$base.99";
        foreach my $i (1 .. 98) {
            my $n    = 99 - $i;
            my $next = $n + 1;
            if (-e "$base.$n") {
                osh_debug "renaming $base.$n to $base.$next";
                if (!rename "$base.$n", "$base.$next") {
                    return R('ERR_INTERNAL', msg => "Couldn't rename '$base.$n' to '$base.$next' ($!)");
                }
                if (-e "$base.$n.metadata" && !rename "$base.$n.metadata", "$base.$next.metadata") {
                    return R('ERR_INTERNAL',
                        msg => "Couldn't rename '$base.$n.metadata' to '$base.$next.metadata' ($!)");
                }
            }
        }
        osh_debug "renaming $base to $base.1";
        if (!rename "$base", "$base.1") {
            return R('ERR_INTERNAL', msg => "Couldn't rename '$base' to '$base.1' ($!)");
        }
        if (-e "$base.metadata" && !rename "$base.metadata", "$base.1.metadata") {
            return R('ERR_INTERNAL', msg => "Couldn't rename '$base.metadata' to '$base.1.metadata' ($!)");
        }
    }
    if (open(my $fdout, '>', $base)) {
        print $fdout "$pass\n";
        close($fdout);
        if ($context eq 'account') {
            chown $Account->uid, $Account->gid, $base;
        }
        chmod 0440, $base;
    }
    else {
        return R('ERR_INTERNAL', msg => "Couldn't create password file in $base ($!)");
    }

    if (open(my $fdout, '>', "$base.metadata")) {
        print $fdout "CREATED_BY=$Self\nBASTION_VERSION=" . $OVH::Bastion::VERSION . "\nCREATION_TIME=" . localtime() . "\nCREATION_TIMESTAMP=" . time() . "\n";
        close($fdout);
        if ($context eq 'account') {
            chown $Account->uid, $Account->gid, "$base.metadata";
        }
        chmod 0440, "$base.metadata";
    }
    else {
        osh_warn "Couldn't create metadata file, proceeding anyway";
    }

    return R('OK', value => {context => $context, group => $shortGroup, account => ($Account ? $Account->name : undef), hashes => $hashes});
}

1;
