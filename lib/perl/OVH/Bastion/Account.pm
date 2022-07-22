package OVH::Bastion::Account;
use common::sense;

use Hash::Util qw{ lock_hashref lock_hashref_recurse unlock_hashref unlock_hashref_recurse lock_ref_value unlock_ref_value };
use List::Util qw{ any none };
use Memoize;
use Cwd; # getcwd

use OVH::Bastion;
use OVH::Result;

use overload (
    '""' => 'name',
    'eq' => 'eq',
    'ne' => 'ne',
);

# instantiate a new account corresponding to the one we have here,
# this in effects nullify all cache handled by memoize for this new instance,
# hence the name ->refresh()
sub refresh {
    my $this = shift;
    return $this->newFromName($this->name);
}

# FIXME double-check that memoize works at the instance level, aka 1 hashcache per instance!!

sub newFromEnv {
    my ($this, %p) = @_;
    return $this->newFromName(OVH::Bastion::get_user_from_env()->value, %p);
}

memoize('newLocalRoot');
sub newLocalRoot {
    my ($this, %p) = @_;
    $p{'isFake'} = 1;
    return $this->newFromName('<root>', %p);
}

# $name can be "joe" or "realm/joe"
sub newFromName {
    my ($objectType, $name, %p) = @_;
    $p{'name'} = $name;
    my $fnret = OVH::Bastion::check_args(\%p,
        mandatory => [qw{ name }],
        optional => [qw{ type }],
        optionalFalseOk => [qw{ isFake }],
    );
    $fnret or return $fnret;

    if ($name eq 'root' && $< == 0) {
        # FIXME for scripts launched as root, such as install and such
        return __PACKAGE__->newLocalRoot();
    }

    my $Account;
    if ($p{'isFake'}) {
        # an isFake account just has a name and doesn't represent any actual bastion account
        $Account = {
            name   => $name,
            sysUser => undef,
            isFake => 1,
        };
    }
    else {
        # FIXME it means we can't newFromName() an account that is INVALID but EXISTING. is this a problem?
        $fnret = _new_from_name(%p);
        $fnret or return $fnret;
        # we have either:
        # R('OK', value => {sysaccount => "realm_$1", realm => $1,    remoteaccount => $2,    account => "$1/$2"});
        # R('OK', value => {sysaccount => $1,         realm => undef, remoteaccount => undef, account => $1});

        $Account = {
            name       => $fnret->value->{'account'},           # joe   or acme/joe
            sysUser    => $fnret->value->{'sysaccount'},        # joe   or realm_acme
            remoteName => $fnret->value->{'remoteaccount'},     # undef or joe
            realm      => $fnret->value->{'realm'},             # undef or acme

            home       => '/home/'.$fnret->value->{'sysaccount'}, # isExisting() will yell if /etc/passwd disagrees
            allowkeeperHome => '/home/allowkeeper/'.$fnret->value->{'sysaccount'},
            passHome        => '/home/'.$fnret->value->{'sysaccount'}.'/pass',
            isFake     => 0,

            # an Account instance may or may not actually exist on the system, until
            # ->isExisting() is called. If the account does exist, said func will
            # set the following params:
            uid        => undef,
            gid        => undef,
            ttyGroup   => undef,
        };
    }

    bless $Account, 'OVH::Bastion::Account';

    lock_hashref_recurse($Account);

    return $Account;
}

BEGIN {
    no strict "refs";

    # simple getters, they have no corresponding setter, as Account objects are immutable
    foreach my $attr (qw{ isFake name sysUser remoteName realm allowkeeperHome ttyGroup }) {
        *$attr = sub {
            my $this = shift;
            return $this->{$attr};
        };
    }

    # almost-simple getters, they just need to have a completely defined Account, hence
    # they ensure that ->isExisting has been called first
    foreach my $attr (qw{ uid gid home }) {
        *$attr = sub {
            my $this = shift;
            if (!defined($this->{$attr})) {
                # check for account's existence and fill $attr if it's the case
                $this->isExisting();
            }
            return $this->{$attr};
        };
    }

    use strict "refs";
}

sub eq {
    my ($this, $that) = @_;
    return (ref $this eq ref $that && $this->name eq $that->name);
}

sub ne {
    my ($this, $that) = @_;
    return !($this eq $that);
}

memoize('getConfig');
sub getConfig {
    my ($this, $compositeKey, %p) = @_;

    my $fnret = OVH::Bastion::check_args(\%p);
    $fnret or return $fnret;

    my ($type, $key) = $compositeKey =~ m{^(private|public)/([a-zA-Z0-9_-]+)$};
    if (!$type || !$key) {
        return R('ERR_INVALID_PARAMETER', msg => "Invalid configuration key asked ($compositeKey)");
    }

    $fnret = $this->check();
    $fnret or return $fnret;

    # private:
    # /home/user/config.key
    # /home/user/config_remotename.key
    # public:
    # /home/allowkeeper/user/config.key
    # /home/allowkeeper/user/config_remotename.key
    my $filename = sprintf("%s/config%s.%s",
        $type eq 'public' ? $this->allowkeeperHome : $this->home,
        $this->remoteName ? '_'.$this->remoteName : '',
        $key
    );

    # getter mode
    my $fh;
    if (!open($fh, '<', $filename)) {
        return R('ERR_CANNOT_OPEN_FILE', msg => "Error while trying to open file $filename for read ($!)");
    }
    my $getvalue = do { local $/ = undef; <$fh> };
    close($fh);
    return R('OK', value => $getvalue);
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
        if (any { $this->sysUser eq $_ } @{$alwaysActiveAccounts->value}) {
            return R('OK');
        }
    }

    # If account has the flag in public config, then is active
    if ($this->getConfig('public/always_active')->value eq 'yes') {
        return R('OK');
    }

    if (!-r -x $checkProgram) {
        OVH::Bastion::warn_syslog("Configured check program '$checkProgram' doesn't exist or is not readable+executable");
        return R('ERR_INTERNAL', msg => "The account activeness check program doesn't exist. Report this to sysadmin!");
    }

    $fnret = OVH::Bastion::execute(cmd => [$checkProgram, $this->sysUser]);
    if (!$fnret) {
        OVH::Bastion::warn_syslog("Failed to execute program '$checkProgram': " . $fnret->msg);
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
            OVH::Bastion::warn_syslog("External account validation program returned status 2 (empty stderr)");
        }
        else {
            OVH::Bastion::warn_syslog("External account validation program returned status 2: " . $_)
              for @{$fnret->value->{'stderr'} || []};
        }
    }
    if ($fnret->value->{'status'} == 4) {
        if (!$fnret->value->{'stderr'}) {
            OVH::Bastion::osh_warn("External account validation program returned status 2 (empty stderr)");
        }
        else {
            OVH::Bastion::osh_warn("External account validation program returned status 2: " . $_)
              for @{$fnret->value->{'stderr'} || []};
        }
    }
    if ($fnret->value->{'status'} >= 2 && $fnret->value->{'status'} <= 4) {
        return R('ERR_UNKNOWN');
    }

    return R('KO_INACTIVE_ACCOUNT');
}

memoize('isTTLNotExpired');
sub isTTLNotExpired {
    my ($this, %p) = @_;
    my $fnret;

    $fnret = $this->isExisting();
    $fnret or return $fnret;

    $fnret = $this->getConfig('private/account_ttl');
    if ($fnret) {
        my $ttl = $fnret->value;
        if ($ttl !~ /^[0-9]+$/) {
            OVH::Bastion::warn_syslog("Invalid TTL value '$ttl' for account '".$this->name."', denying access");
            return R('ERR_INVALID_TTL',
                msg => "Issue with your account TTL configuration, access denied. "
                  . "Please check with an administrator");
        }

        $fnret = $this->getConfig('private/creation_timestamp');
        my $created = $fnret->value;
        if ($created !~ /^[0-9]+$/) {
            OVH::Bastion::warn_syslog("Invalid account creation time '$created' for account '".$this->name."', denying access");
            return R('ERR_INVALID_TTL',
                msg => "Issue with your account TTL configuration, access denied. "
                  . "Please check with an administrator");
        }

        my $expiryTime = $created + $ttl;
        if ($expiryTime < time()) {
            $fnret = OVH::Bastion::duration2human(seconds => time() - $expiryTime);
            return R(
                'KO_TTL_EXPIRED',
                msg   => "Sorry ".$this->name.", your account TTL has expired since " . $fnret->value->{'human'},
                value => {expiry_time => $expiryTime, details => $fnret->value}
            );
        }

        $fnret = OVH::Bastion::duration2human(seconds => $expiryTime - time());
        return R('OK_TTL_VALID', value => {expiry_time => $expiryTime, details => $fnret->value});
    }
    return R('OK_NO_TTL');
}

memoize('isNotExpired');
sub isNotExpired {
    my ($this, %p) = @_;
    my $fnret;

    $fnret = $this->isExisting();
    $fnret or return $fnret;

    # accountMaxInactiveDays is the max allowed inactive days to not block login. 0 means feature disabled.
    $fnret = OVH::Bastion::config('accountMaxInactiveDays');
    my $accountMaxInactiveDays = ($fnret && $fnret->value > 0) ? $fnret->value : 0;

    # some accounts might have a specific configuration overriding the global one
    $fnret = $this->getConfig('public/max_inactive_days');
    if ($fnret) {
        $accountMaxInactiveDays = $fnret->value;
    }

    my $isFirstLogin;
    my $lastlog;
    # XXX HERE
    my $filepath = sprintf("/home/%s/lastlog%s", $this->sysUser, $this->remoteName ? "_".$this->remoteName : ""); # FIXME move login into Account
    my $value    = {filepath => $filepath};
    if (-e $filepath) {
        $isFirstLogin = 0;
        $lastlog      = (stat(_))[9];
        OVH::Bastion::osh_debug("is_account_nonexpired: got lastlog date: $lastlog");

        # if lastlog file is available, fetch some info from it
        if (open(my $lastloginfh, "<", $filepath)) {
            my $info = <$lastloginfh>;
            chomp $info;
            close($lastloginfh);
            $value->{'info'} = $info;
        }
    }
    else {
        my ($previousDir) = getcwd() =~ m{^(/[a-z0-9_./-]+)}i;
        if (!chdir("/home/".$this->sysUser)) {
            OVH::Bastion::osh_debug("is_account_nonexpired: no exec access to the folder!");
            return R('ERR_NO_ACCESS', msg => "No read access to this account folder to compute last login time");
        }
        chdir($previousDir);
        $isFirstLogin = 1;

        # get the account creation timestamp as the lastlog
        $fnret = $this->getConfig('private/creation_timestamp');
        if ($fnret && $fnret->value) {
            $lastlog = $fnret->value;
            OVH::Bastion::osh_debug("is_account_nonexpired: got creation date from config.creation_timestamp: $lastlog");
        }
        elsif (-e sprintf("/home/%s/accountCreate.comment", $this->sysUser)) {

            # fall back to the stat of the accountCreate.comment file
            $lastlog = (stat(_))[9];
            OVH::Bastion::osh_debug("is_account_nonexpired: got creation date from accountCreate.comment stat: $lastlog");
        }
        else {
            # last fall back to the stat of the ttyrec/ folder
            $lastlog = (stat(sprintf("/home/%s/ttyrec", $this->sysUser)))[9];
            OVH::Bastion::osh_debug("is_account_nonexpired: got creation date from ttyrec/ stat: $lastlog");
        }
    }

    my $seconds = time() - $lastlog;
    my $days    = int($seconds / 86400);
    $value->{'days'}                = $days;
    $value->{'seconds'}             = $seconds;
    $value->{'already_seen_before'} = !$isFirstLogin;
    OVH::Bastion::osh_debug("Last account activity: $days days ago");

    if ($accountMaxInactiveDays == 0) {

        # no expiration configured, allow login and return some info
        return R('OK_FIRST_LOGIN',               value => $value) if $isFirstLogin;
        return R('OK_EXPIRATION_NOT_CONFIGURED', value => $value);
    }
    else {
        if ($days < $accountMaxInactiveDays) {

            # expiration configured, but account not expired, allow login
            return R('OK_NOT_EXPIRED', value => $value);
        }
        else {
            # account expired, deny login
            my $msg = OVH::Bastion::config("accountExpiredMessage")->value;
            $msg = "Sorry, but your account has expired (#DAYS# days), access denied by policy." if !$msg;
            $msg =~ s/#DAYS#/$days/g;
            return R(
                'KO_EXPIRED',
                value => $value,
                msg   => $msg,
            );
        }
    }
    return R('ERR_INTERNAL_ERROR');
}

memoize('isExisting');
sub isExisting {
    my ($this, %p) = @_;
    my $fnret = OVH::Bastion::check_args(\%p,
        optional => [qw{ nocache }],
    );
    $fnret or return $fnret;

    my %entry;
    if (OVH::Bastion::is_mocking()) {
        my @fields = OVH::Bastion::mock_get_account_entry(account => $this->sysUser);
        %entry = (
            name   => $fields[0],
            passwd => $fields[1],
            uid    => $fields[2],
            gid    => $fields[3],
            gcos   => $fields[4],
            home   => $fields[5],
            shell  => $fields[6],
        );
    }
    else {
        my $fnret = OVH::Bastion::sys_getpw_name(name => $this->sysUser, cache => !$p{'nocache'});
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

        my ($newdir) = $entry{'home'} =~ m{([/a-zA-Z0-9._-]+)};                   # untaint
        if ($newdir ne $entry{'home'}) {
            return R('ERR_SECURITY_VIOLATION', msg => "Forbidden characters in account home directory")
        }
        $entry{'home'} = $newdir;

        if ($entry{'home'} ne $this->home) {
            warn_syslog(sprintf("Account %s home is '%s' instead of '%s'", $this->name, $entry{'home'}, $this->home);
            return R('ERR_SECURITY_VIOLATION', msg => "Mismatch between theoretical and actual home location");
        }

        $entry{'ttyGroup'} = $this->sysUser."-tty";
        if (!getgrnam($entry{'ttyGroup'})) {
            # no corresponding tty group? hmm, weird, but not fatal...
            $entry{'ttyGroup'} = undef;
        }

        foreach my $key (qw{ uid gid home ttyGroup }) {
            unlock_ref_value($this, $key);
            $this->{$key} = $entry{$key};
            lock_ref_value($this, $key);
        }

        return R('OK');
    }
    return R('KO_NOT_FOUND', msg => sprintf("Account '%s' doesn't exist", $this->name));
}

# checks that isExisting() and potentially other tiny things to ensure the account is sane
# do NOT memoize this one, as we're looking at global env and $<, we memoize check() instead,
# which is generic for all accounts (not only for the account that is running the code)
sub selfCheck {
    my ($this, %p) = @_;
    my $fnret;

    # if we are manipulating the a localRoot account, and we're running under root
    # privileges without sudo, then deem this account as valid so that scripts running
    # directly under root (such as the install script) find that $this is valid and carry on
    if ($this->name eq '<root>' && $this->isFake && $< == 0 && !$ENV{'SUDO_USER'}) {
        return R('OK');
    }

    # this should always be set
    if (!$ENV{'USER'}) {
        OVH::Bastion::warn_syslog("Unset USER envvar while checking account ".$this->name);
        return R('KO_INVALID_ACCOUNT', msg => "Your USER envvar is not set");
    }

    # run the rest of the logic that is common for other accounts that are not "us"
    $fnret = $this->check();
    $fnret or return $fnret;

    # do NOT do this check before calling ->check() because the latter is responsible for
    # calling ->isExisting which in turn ensures that sysUser is set up accordingly
    if ($ENV{'SUDO_USER'}) {
        if ($this->sysUser ne $ENV{'SUDO_USER'}) {
            OVH::Bastion::warn_syslog(sprintf(
                "Mismatching SUDO8USER envvar '%s' while checking account '%s' with sysUser '%s'",
                $ENV{'SUDO_USER'}, $this->name, $this->sysUser
            ));
            return R('KO_INVALID_ACCOUNT', msg => "Your SUDO_USER envvar doesn't match your system account $ENV{'SUDO_USER'} and ".$this->sysUser); # FIXME remove the verbose MIGRA
        }
    }
    elsif ($this->sysUser ne $ENV{'USER'}) {
        OVH::Bastion::warn_syslog(sprintf(
            "Mismatching USER envvar '%s' while checking account '%s' with sysUser '%s'",
            $ENV{'USER'}, $this->name, $this->sysUser
        ));
        return R('KO_INVALID_ACCOUNT', msg => "Your USER envvar doesn't match your system account $ENV{'USER'} and ".$this->sysUser);
    }

    return R('OK');
}

# checks that isExisting() and potentially other tiny things to ensure the account is sane
memoize('check');
sub check {
    my ($this, %p) = @_;
    my $fnret;

    $fnret = $this->isExisting();
    $fnret or return $fnret;

    if (!-d $this->home) {
        return R('KO_INVALID_DIRECTORY', msg => "This account's home directory doesn't exist");
    }

    if (!-d $this->allowkeeperHome) {
        return R('KO_INVALID_DIRECTORY', msg => "This account's allowkeeper home directory doesn't exist");
    }

    return R('OK');
}

# return R('OK', value => {sysaccount => "realm_$1", realm => $1,    remoteaccount => $2,    account => "$1/$2"}); # untainted
# return R('OK', value => {sysaccount => $1,         realm => undef, remoteaccount => undef, account => $1});  # untainted
sub _new_from_name {
    my %p = @_;
    my $fnret = OVH::Bastion::check_args(\%p,
        mandatory => [qw{ name }],
        optional => [qw{ type }]
    );
    $fnret or return $fnret;

    my $name = $p{'name'};
    my $type = $p{'type'} || 'regular';
    # - local: disallow realm-formatted accounts aka $realm/$remoteself
    # - remote: allow only realm-formatted accounts aka $realm/$remoteself
    # - regular: either a local or remote account (autodetect and allow both)
    # - realm: a realm support account, must start with realm_*
    # - account: either a local, remote or realm support account (autodetect and allow these 3)
    # - incoming: either a local account or a realm account, in which case we'll autodetect
    #             the remote account (through LC_BASTION) and setup accordingly. If we don't find a remote account
    #             and we have a realm account, deny it (return an error). Mainly used to create an Account instance
    #             from an ingress connection information.
    # - group: system user with the same uid than a bastion group's gid, must start with key*
    #        FIXME: type=group is actually not an ::Account and shouldn't be there

    # if both types are allowed, resolve whether it looks like a local or remote account
    # so that the proper tests are done in the rest of the func
#MIGRA OVH::Bastion::osh_warn("type=$type name=$name caller1=".(caller(1))[3]." and caller2=".(caller(2))[3]." and caller3=".(caller(3))[3]." from $0");
    if ($type eq 'regular') {
        $type = ($name =~ m{/} ? 'remote' : 'local');
    }
    elsif ($type eq 'account') {
        if ($name =~ /^realm_/) {
            $type = 'realm';
        }
        else {
            $type = ($name =~ m{/} ? 'remote' : 'local');
        }
    }
    my $whatis = ($type eq 'remote' ? "Realm" : "Account");

    if ($name =~ m{/} && $type ne 'remote') {
        return R('KO_REALM_FORBIDDEN', msg => "$whatis name must not contain any '/'");
    }
    elsif ($name !~ m{/} && $type eq 'remote') {
        return R('KO_LOCAL_FORBIDDEN', msg => "$whatis name must contain a '/'");
    }
    elsif ($name =~ m/^key/i && $type ne 'group') {
        return R('KO_FORBIDDEN_PREFIX', msg => "$whatis name contains an unauthorized key prefix");
    }
    elsif ($name !~ m/^key/i && $type eq 'group') {
        return R('KO_BAD_PREFIX', msg => "$whatis should start with the group prefix");
    }
    elsif ($name =~ m/^realm_/ && none { $type eq $_ } qw{ realm incoming }) {
        return R('KO_FORBIDDEN_PREFIX', msg => "$whatis name contains an unauthorized realm prefix type=$type name=$name");
    }
    elsif ($name !~ m/^realm_/ && $type eq 'realm') {
        return R('KO_BAD_PREFIX', msg => "$whatis should start with the realm prefix");
    }
    elsif ($name =~ m/^[-.]/) {
        return R('KO_FORBIDDEN_PREFIX', msg => "$whatis name must not start with a '-' nor a '.'");
    }
    elsif ($name =~ m/-tty$/i) {
        return R('KO_FORBIDDEN_SUFFIX', msg => "$whatis name contains an unauthorized suffix");
    }
    elsif (grep { $name eq $_ } qw{ root proxyhttp keykeeper passkeeper logkeeper realm realm_realm }) {
        return R('KO_FORBIDDEN_NAME', msg => "$whatis name is reserved");
    }
    elsif ($name =~ m{^([a-zA-Z0-9-]+)/([a-zA-Z0-9._-]+)$} && $type eq 'remote') {

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
        $name = $1; # untaint

        if (length($name) < 2) {
            return R('KO_TOO_SMALL', msg => "$whatis name is too small, length($name) < 2");
        }

        # 28 because all accounts have a corresponding "-tty" group, and 32 - length(-tty) == 28
        elsif (length($name) > 28) {
            return R('KO_TOO_LONG', msg => "$whatis name is too long, length($name) > 28");
        }

        if ($type eq 'incoming' && $name =~ /realm_(.+)$/) {
            # if we have an account starting with realm_, in this case our caller wants us to find the correspoding
            # remote account, and fail if we don't
            my $remoteAccountRealm = $1;
            if (length($remoteAccountRealm) < 2) {
                return R('KO_TOO_SMALL', msg => "$whatis remote account realm name is too small, length($remoteAccountRealm) < 2");
            }

            if ($ENV{'LC_BASTION'}) {
                my $remoteAccountName = $ENV{'LC_BASTION'};
                if (length($remoteAccountName) < 2) {
                    return R('KO_TOO_SMALL', msg => "$whatis remote account name is too small, length($remoteAccountRealm) < 2");
                }
                my $remoteAccount = sprintf("%s/%s", $remoteAccountRealm, $remoteAccountName);
                return _new_from_name(name => $remoteAccount, type => "remote");
            }
            else {
                return R('KO_INVALID_ACCOUNT', msg => "Attempted to use a realm account but not from another bastion");
            }
        }

        return R('OK', value => {sysaccount => $name, realm => undef, remoteaccount => undef, account => $name, type => 'local'});  # untainted
    }
    else {
        return R('KO_FORBIDDEN_CHARS', msg => "$whatis name '$name' contains forbidden characters");
    }
    return R('ERR_IMPOSSIBLE_CASE');
}

sub _has_role {
    my ($this, $role, $configList, $sysGroup) = @_;

    my $fnret = $this->isExisting();
    $fnret or return $fnret;

    if (OVH::Bastion::is_user_in_group(group => $sysGroup, user => $this->sysUser)) {
        if (!$configList || any { $this->name eq $_ } @{ OVH::Bastion::config($configList)->value || [] }) {
            return R('OK', msg => "Account ".$this->name." is a bastion $role");
        }
    }
    return R('KO_ACCESS_DENIED', msg => "Account ".$this->name." is not a bastion $role");
}

memoize('isAdmin');
sub isAdmin      { my $this = shift; return $this->_has_role("administrator", "adminAccounts", "osh-admin"); }
memoize('isSuperOwner');
sub isSuperOwner { my $this = shift; return $this->_has_role("superowner", "superOwnerAccounts", "osh-superowner") || $this->isAdmin; }
memoize('isAuditor');
sub isAuditor    { my $this = shift; return $this->_has_role("auditor", undef, "osh-auditor"); }

# return a hash with keys being the bastion group names and as values,
# a hash of relations to this account, i.e. member, guest, aclkeeper,
# gatekeeper, owner.
memoize('getGroups');
sub getGroups {
    my ($this, %p) = @_;

    my $fnret = OVH::Bastion::check_args(\%p,
        optionalFalseOk => ['cache'] # allow use of sys_getgr_all's cache
    );

    $fnret = $this->isExisting();
    $fnret or return $fnret;

    # we loop through all the system groups to find the ones having user
    # as a member (here, member of the group just means member of the system
    # group, this translate as either "member" or "guest" of the bastion group).
    # for the key* groups, member means aclkeeper, gatekeeper or owner of the
    # corresponding bastion group
    $fnret = OVH::Bastion::sys_getgr_all(cache => $p{'cache'});
    $fnret or return $fnret;

    my %result;
    foreach my $sysgroup (keys %{$fnret->value}) {
        # we must be a member of this sysgroup
        next if (none { $this->sysUser eq $_ } @{ $fnret->value->{$sysgroup}->{'members'} });

        ## no critic(RegularExpressions::ProhibitUnusedCapture) # false positive
        if ($sysgroup =~ /^key(?<groupname>.+?)(-(?<type>gatekeeper|aclkeeper|owner))?$/) {
            my $groupname = $+{'groupname'};
            my $type = $+{'type'};
            if (!$type) {
                # member or guest?
                my $prefix = $this->remoteName ? "allowed_".$this->remoteName : "allowed";
                if (-l sprintf("%s/%s.ip.%s", $this->allowkeeperHome, $prefix, $groupname)) {
                    $type = 'member';
                }
                else {
                    $type = 'guest'; # FIXME later: we should check if there is at least one allowed.ip.partial
                }
            }
            $result{$groupname}{$type} = 1;
        }
    }
    return R('OK', value => \%result);
}

memoize('canExecutePlugin');
sub canExecutePlugin {
    my ($this, $plugin, %p) = @_;
    $p{'plugin'} = $plugin;
    my $fnret = OVH::Bastion::check_args(\%p,
        mandatory => [qw{ plugin }],
    );
    $fnret or return $fnret;

    $fnret = $this->isExisting();
    $fnret or return $fnret;

    # sanitize for -T
    my ($sanePlugin) = $plugin =~ /^([a-zA-Z0-9_-]+)$/;
    if ($plugin ne $sanePlugin) {
        return R('ERR_INVALID_PARAMETER', msg => "Parameter 'plugin' contains invalid characters");
    }
    $plugin = $sanePlugin;

    my $path_plugin = $OVH::Bastion::BASEPATH . '/bin/plugin';

    # first, check if the plugin is readonly-proof if we are in readonly mode (slave)
    $fnret = OVH::Bastion::config('readOnlySlaveMode');
    $fnret or return $fnret;
    if ($fnret->value and not OVH::Bastion::is_plugin_readonly_proof(plugin => $plugin)) {
        return R('ERR_READ_ONLY',
            msg => "You can't use this command on this bastion instance, as this is a write/modify command,\n"
              . "and this bastion instance is read-only (slave). Please do this on the master instance of my cluster instead!"
        );
    }

    # realm accounts are very restricted
    if ($this->name =~ m{^realm_}) { # FIXME ->type eq 'shared'?
        return R('ERR_SECURITY_VIOLATION', msg => "Realm support accounts can't execute any plugin by themselves");
    }
    if ($this->name =~ m{/} && !grep { $plugin eq $_ } # FIXME ->type eq 'remote'?
        qw{ alive help info mtr nc ping selfForgetHostKey selfListAccesses selfListEgressKeys })
    {
        return R('ERR_REALM_USER',
            msg => "Realm accounts can't execute this plugin, use --osh help to get the allowed plugin list");
    }

    # open plugins, always start to look there
    if (-f ($path_plugin . '/open/' . $plugin)) {
        return R('OK', value => {fullpath => $path_plugin . '/open/' . $plugin, type => 'open', plugin => $plugin});
    }

    # aclkeeper/gatekeepers/owners plugins
    if (   -f ($path_plugin . '/group-aclkeeper/' . $plugin)
        or -f ($path_plugin . '/group-gatekeeper/' . $plugin)
        or -f ($path_plugin . '/group-owner/' . $plugin))
    {

        # need to parse group to see if maybe member of group-gatekeeper or group-owner (or super owner)
        $fnret = $this->getGroups();
        $fnret or return $fnret;

        my %groups = %{$fnret->value};

        foreach my $type (qw{ aclkeeper gatekeeper owner }) {
            if (-f "$path_plugin/group-$type/$plugin") {

                # we can always execute these commands if we are a super owner
                my $canDo = $this->isSuperOwner ? 1 : 0;

                # or if we are $type on at least one group
                $canDo++ if (any { $_->{$type} } values %groups);

                return R(
                    'OK',
                    value => {
                        fullpath => "$path_plugin/group-$type/$plugin",
                        type     => "group-$type",
                        plugin   => $plugin
                    }
                ) if $canDo;
                return R(
                    'KO_PERMISSION_DENIED',
                    value => {type => "group-type", plugin => $plugin},
                    msg   => "Sorry, you must be a group $type to use this command"
                );
            }
        }

        # unreachable code:
        return R(
            'KO_PERMISSION_DENIED',
            value => {type => 'group-unknown', plugin => $plugin},
            msg   => "Permission denied"
        );
    }

    # restricted plugins (osh-* system groups based)
    if (-f ($path_plugin . '/restricted/' . $plugin)) {
        if (OVH::Bastion::is_user_in_group(user => $this->sysUser, group => "osh-$plugin", cache => 1)) {
            return R('OK',
                value => {fullpath => $path_plugin . '/restricted/' . $plugin, type => 'restricted', plugin => $plugin}
            );
        }
        else {
            return R(
                'KO_PERMISSION_DENIED',
                value => {type => 'restricted', plugin => $plugin},
                msg   => "Sorry, this command is restricted and requires you to be specifically granted"
            );
        }
    }

    # admin plugins
    if (-f ($path_plugin . '/admin/' . $plugin)) {
        if ($this->isAdmin()) {
            return R('OK',
                value => {fullpath => $path_plugin . '/admin/' . $plugin, type => 'admin', plugin => $plugin});
        }
        else {
            return R(
                'KO_PERMISSION_DENIED',
                value => {type => 'admin', plugin => $plugin},
                msg   => "Sorry, this command is only available to bastion admins"
            );
        }
    }

    # still here ? sorry.
    return R('KO_UNKNOWN_PLUGIN', value => {type => 'open'}, msg => "Unknown command");
}

1;
