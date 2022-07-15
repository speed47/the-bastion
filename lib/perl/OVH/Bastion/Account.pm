package OVH::Bastion::Account;
use common::sense;

use Hash::Util qw{ lock_hashref lock_hashref_recurse unlock_hashref unlock_hashref_recurse lock_ref_value unlock_ref_value };
use List::Util qw{ any };
use Memoize;

use OVH::Bastion;
use OVH::Result;

sub refresh {
    my $this = shift;
    return newFromName(__PACKAGE__, $this->name);
}

# FIXME double-check that memoize works at the instance level, aka 1 hashcache per instance!!

sub newFromEnv {
    return newFromName(__PACKAGE__, OVH::Bastion::get_user_from_env()->value);
}

memoize('newInvalid');
sub newInvalid {
    return newFromName(__PACKAGE__, '<none>');
}

# $name can be "joe" or "realm/joe"
sub newFromName {
    my $objectType = shift;
    my $name = shift;

    # FIXME it means we can't newFromName() an account that is INVALID but EXISTING. is this a problem?
    my $fnret = _new_from_name(name => $name);
    # return R('OK', value => {sysaccount => "realm_$1", realm => $1,    remoteaccount => $2,    account => "$1/$2"}); # untainted
    # return R('OK', value => {sysaccount => $1,         realm => undef, remoteaccount => undef, account => $1});  # untainted
    $fnret or return $fnret;

    my $Account = {
        name       => $fnret->value->{'account'},           # joe or realmname/joe
        sysName    => $fnret->value->{'sysaccount'}, # joe or realm_nameoftherealm
        remoteName => $fnret->value->{'remoteaccount'},
        realm      => $fnret->value->{'realm'},
        type       => $fnret->value->{'type'},
        uid        => undef, # set in JIT by isExisting()
        gid        => undef, # set in JIT by isExisting()
        home       => undef, # set in JIT by isExisting()
    };

    bless $Account, 'OVH::Bastion::Account';

    lock_hashref_recurse($Account);

    return $Account;
}

sub name {
    my $this = shift;
    return $this->{'name'};
}

sub sysName {
    my $this = shift;
    return $this->{'sysName'};
}

sub remoteName {
    my $this = shift;
    return $this->{'remoteName'};
}

sub realm {
    my $this = shift;
    return $this->{'realm'};
}

sub uid {
    my $this = shift;
    if (!defined($this->{'uid'})) {
        # check for account's existence and fill uid if it's the case
        $this->isExisting();
    }
    return $this->{'uid'};
}

sub gid {
    my $this = shift;
    if (!defined($this->{'gid'})) {
        # check for account's existence and fill gid if it's the case
        $this->isExisting();
    }
    return $this->{'gid'};
}

sub home {
    my $this = shift;
    if (!defined($this->{'home'})) {
        # check for account's existence and fill home if it's the case
        $this->isExisting();
    }
    return $this->{'home'};
}

memoize('getConfig');
sub getConfig {
    my $this = shift;
    my $key  = shift;

    # key => OVH::Bastion::OPT_ACCOUNT_ALWAYS_ACTIVE,  public  => 1
    # TODO
    return 1;
}

memoize('isActive');
sub isActive {
    my $this = shift;
    my $fnret;

    $fnret = $this->isExisting();
    $fnret or return $fnret;

    my $checkProgram = OVH::Bastion::config('accountExternalValidationProgram')->value;
    if (!$checkProgram) {
        return R('OK_FEATURE_DISABLED');
    }

    # If in alwaysActive, then is active
    my $alwaysActiveAccounts = OVH::Bastion::config('alwaysActiveAccounts');
    if ($alwaysActiveAccounts and $alwaysActiveAccounts->value) {
        if (grep { $this->sysUser eq $_ } @{$alwaysActiveAccounts->value}) {
            return R('OK');
        }
    }

    # If account has the flag in public config, then is active
    if ($this->getConfig('always_active')) {
        return R('OK');
    }

    if (!-r -x $checkProgram) {
        warn_syslog("Configured check program '$checkProgram' doesn't exist or is not readable+executable");
        return R('ERR_INTERNAL', msg => "The account activeness check program doesn't exist. Report this to sysadmin!");
    }

    $fnret = OVH::Bastion::execute(cmd => [$checkProgram, $this->sysUser]);
    if (!$fnret) {
        warn_syslog("Failed to execute program '$checkProgram': " . $fnret->msg);
        return $this->_cache(R('ERR_INTERNAL', msg => "The account activeness check program failed. Report this to sysadmin!"));
    }

=cut exit code meanings of the account activeness check program are as follows:
    EXIT_ACTIVE                => 0,
    EXIT_INACTIVE              => 1,
    EXIT_UNKNOWN               => 2,
    EXIT_UNKNOWN_SILENT_ERROR  => 3,
    EXIT_UNKNOWN_NOISY_ERROR   => 4,
=cut

    if ($fnret->value->{'status'} == 0) {
        return R('OK');
    }
    if ($fnret->value->{'status'} == 3) {
        if (!$fnret->value->{'stderr'}) {
            warn_syslog("External account validation program returned status 2 (empty stderr)");
        }
        else {
            warn_syslog("External account validation program returned status 2: " . $_)
              for @{$fnret->value->{'stderr'} || []};
        }
    }
    if ($fnret->value->{'status'} == 4) {
        if (!$fnret->value->{'stderr'}) {
            osh_warn("External account validation program returned status 2 (empty stderr)");
        }
        else {
            osh_warn("External account validation program returned status 2: " . $_)
              for @{$fnret->value->{'stderr'} || []};
        }
    }
    if ($fnret->value->{'status'} >= 2 && $fnret->value->{'status'} <= 4) {
        return R('ERR_UNKNOWN');
    }

    return R('KO_INACTIVE_ACCOUNT');
}

memoize('isExisting');
sub isExisting {
    my ($this, %params) = @_;
    my $nocache = $params{'nocache'};

    my %entry;
    if (OVH::Bastion::is_mocking()) {
        my @fields = OVH::Bastion::mock_get_account_entry(account => $this->sysName);
        %entry = (
            name   => $fields[0],
            passwd => $fields[1],
            uid    => $fields[2],
            gid    => $fields[3],
            gcos   => $fields[4],
            dir    => $fields[5],
            shell  => $fields[6],
        );
    }
    else {
        my $fnret = OVH::Bastion::sys_getpw_name(name => $this->sysName, cache => !$nocache);
        if ($fnret) {
            %entry = %{$fnret->value};
        }
    }

    if (%entry) {
        my ($newname) = $entry{'name'} =~ m{([a-zA-Z0-9._-]+)};
        return R('ERR_SECURITY_VIOLATION', msg => "Forbidden characters in account name")
          if ($newname ne $entry{'name'});
        $entry{'name'} = $newname;    # untaint

        if ($entry{'shell'} ne $OVH::Bastion::BASEPATH . "/bin/shell/osh.pl") {
            # msg is the same as when the account is /really/ not found (see below), voluntarily
            return R('KO_NOT_FOUND', msg => sprintf("Account '%s' doesn't exist", $this->name));
        }

        my ($newdir) = $entry{'dir'} =~ m{([/a-zA-Z0-9._-]+)};                   # untaint
        if ($newdir ne $entry{'dir'}) {
            return R('ERR_SECURITY_VIOLATION', msg => "Forbidden characters in account home directory")
        }
        $entry{'dir'} = $newdir;                                                 # untaint

        $entry{'home'} = $entry{'dir'};
        foreach my $key (qw{ uid gid home }) {
            unlock_ref_value($this, $key);
            $this->{$key} = $entry{$key};
            lock_ref_value($this, $key);
        }

        return R('OK');
    }
    return R('KO_NOT_FOUND', msg => sprintf("Account '%s' doesn't exist", $this->name));
}

# check if account name is valid, i.e. non-weird chars and non reserved parts
#memoize('isValid');
sub _new_from_name {
    my %params  = @_;
    my $name = $params{'name'};
    my $accountType = $params{'accountType'} || 'normal'; # normal (local account or $realm/$remoteself formatted account) | group (must start with key*) | realm (must start with realm_*)
    my $localOnly   = $params{'localOnly'};               # for accountType == normal, disallow realm-formatted accounts ($realm/$remoteself)
    my $realmOnly   = $params{'realmOnly'};               # for accountType == normal, allow only realm-formatted accounts ($realm/$remoteself)

    # FIXME
    die if $accountType ne 'normal';
    die if $localOnly;
    die if $realmOnly;

    my $whatis = ($accountType eq 'realm' ? "Realm" : "Account");

    if (!defined($name)) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing 'name' parameter");
    }
    if ($localOnly && $name =~ m{/}) {
        return R('KO_REALM_FORBIDDEN', msg => "$whatis name must not contain any '/'");
    }
    elsif ($realmOnly && $name !~ m{/}) {
        return R('KO_LOCAL_FORBIDDEN', msg => "$whatis name must contain a '/'");
    }
    elsif ($name =~ m/^[-.]/) {
        return R('KO_FORBIDDEN_PREFIX', msg => "$whatis name must not start with a '-' nor a '.'");
    }
    elsif ($name =~ m/-tty$/i) {
        return R('KO_FORBIDDEN_SUFFIX', msg => "$whatis name contains an unauthorized suffix");
    }
    elsif ($name =~ m/^key/i && $accountType ne 'group') {
        return R('KO_FORBIDDEN_PREFIX', msg => "$whatis name contains an unauthorized key prefix");
    }
    elsif ($name !~ m/^key/i && $accountType eq 'group') {
        return R('KO_BAD_PREFIX', msg => "$whatis should start with the group prefix");
    }
    elsif ($name =~ m/^realm_/ && $accountType ne 'realm') {
        return R('KO_FORBIDDEN_PREFIX', msg => "$whatis name contains an unauthorized realm prefix");
    }
    elsif ($name !~ m/^realm_/ && $accountType eq 'realm') {
        return R('KO_BAD_PREFIX', msg => "$whatis should start with the realm prefix");
    }
    elsif (grep { $name eq $_ } qw{ root proxyhttp keykeeper passkeeper logkeeper realm realm_realm }) {
        return R('KO_FORBIDDEN_NAME', msg => "$whatis name is reserved");
    }
    elsif ($name =~ m{^([a-zA-Z0-9-]+)/([a-zA-Z0-9._-]+)$} && $accountType eq 'normal') {

        # 32 is the max Linux user length
        if (length("realm_$1") > 32) {
            return R('KO_TOO_LONG', msg => "$whatis name is too long, length(realm_$1) > 32");
        }
        elsif (length($1) < 2) {
            return R('KO_TOO_SMALL', msg => "$whatis name is too long, length($1) < 2");
        }

        # 28 because all accounts have a corresponding "-tty" group, and 32 - length(-tty) == 28
        elsif (length($2) > 28) {
            return R('KO_TOO_LONG', msg => "Remote account name is too long, length($2) > 28");
        }
        elsif (length($2) < 2) {
            return R('KO_TOO_SMALL', msg => "Remote account name is too short, length($2) < 2");
        }
        return R('OK', value => {sysaccount => "realm_$1", realm => $1, remoteaccount => $2, account => "$1/$2", type => 'realm'}); # untainted
    }
    elsif ($name =~ m/^([a-zA-Z0-9._-]+)$/) {
        if (length($1) < 2) {
            return R('KO_TOO_SMALL', msg => "$whatis name is too small, length($1) < 2");
        }

        # 28 because all accounts have a corresponding "-tty" group, and 32 - length(-tty) == 28
        elsif (length($1) > 28) {
            return R('KO_TOO_LONG', msg => "$whatis name is too long, length($1) > 28");
        }
        return R('OK', value => {sysaccount => $1, realm => undef, remoteaccount => undef, account => $1, type => 'local'});  # untainted
    }
    else {
        return R('KO_FORBIDDEN_CHARS', msg => "$whatis name '$name' contains forbidden characters");
    }
    return R('ERR_IMPOSSIBLE_CASE');
}

memoize('isAdmin');
sub isAdmin {
    my $this = shift;

    my $fnret = $this->isExisting();
    $fnret or return $fnret;

    my $adminList = OVH::Bastion::config('adminAccounts')->value();
    if (any { $this->name eq $_ } @$adminList) {
        if (OVH::Bastion::is_user_in_group(group => "osh-admin", user => $this->name)) {
            return R('OK', msg => "Account ".$this->name." is a bastion administrator");
        }
    }
    return R('KO_ACCESS_DENIED', msg => "Account ".$this->name." is not a bastion administrator");
}

=cut
sub isValidAndExisting {
    my $this = shift;
    my %params = @_;
    my $fnret;

    # return cached Result if we have it
    $this->_cached() and return;

    $fnret = $this->isValid();
    $fnret or return $this->_cache($fnret);

    $fnret = $this->isExisting(checkBastionShell => 1, cache => $params{'cache'});
    $fnret or return $this->_cache($fnret);

    return R('OK');
}
=cut

1;
