package OVH::Bastion::Account;
use common::sense;

use Hash::Util qw{ lock_hashref lock_hashref_recurse unlock_hashref unlock_hashref_recurse lock_ref_value unlock_ref_value };
use List::Util qw{ any };
use Memoize;

use OVH::Bastion;
use OVH::Result;

# instantiate a new account corresponding to the one we have here,
# this in effects nullify all cache handled by memoize for this new instance,
# hence the name ->refresh()
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
        allowkeeperHome => '/home/allowkeeper/'.$fnret->value->{'account'},
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

sub allowkeeperHome {
    my $this = shift;
    return $this->{'allowkeeperHome'};
}

memoize('getConfig');
sub getConfig {
    my ($this, %params) = @_;
    my $compositeKey = $params{'key'};
    my $fnret;

    if (!$compositeKey) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing required parameter 'key'");
    }

    my ($type, $key) = $compositeKey =~ m{^(private|public)/([a-zA-Z0-9_-]+)$});
    if (!$type || !$key) {
        return R('ERR_INVALID_PARAMETER', msg => "Invalid configuration key asked ($compositeKey)");
    }

    $this->check() or return;

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
        if (grep { $this->sysUser eq $_ } @{$alwaysActiveAccounts->value}) {
            return R('OK');
        }
    }

    # If account has the flag in public config, then is active
    if ($this->getConfig('public/always_active')) {
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

memoize('isTTLNotExpired');
sub isTTLNotExpired {
    my ($this, %params) = @_;
    my $fnret;

    $this->isExisting() or return;

    $fnret = $this->getConfig('private/account_ttl');
    if ($fnret) {
        my $ttl = $fnret->value;
        if ($ttl !~ /^[0-9]+$/) {
            warn_syslog("Invalid TTL value '$ttl' for account '".$this->name."', denying access");
            return R('ERR_INVALID_TTL',
                msg => "Issue with your account TTL configuration, access denied. "
                  . "Please check with an administrator");
        }

        $fnret = $this->getConfig('private/creation_timestamp');
        my $created = $fnret->value;
        if ($created !~ /^[0-9]+$/) {
            warn_syslog("Invalid account creation time '$created' for account '".$this->name."', denying access");
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
    my ($this, %params) = @_;

    $this->isExisting() or return;

    # accountMaxInactiveDays is the max allowed inactive days to not block login. 0 means feature disabled.
    my $accountMaxInactiveDays = 0;
    my $fnret                  = OVH::Bastion::config('accountMaxInactiveDays');
    if ($fnret and $fnret->value > 0) {
        $accountMaxInactiveDays = $fnret->value;
    }

    # some accounts might have a specific configuration overriding the global one
    $fnret = $this->getConfig('public/max_inactive_days');
    if ($fnret) {
        $accountMaxInactiveDays = $fnret->value;
    }

    my $isFirstLogin;
    my $lastlog;
    # XXX HERE
    my $filepath = sprintf("/home/%s/lastlog%s", $this->name, $this->remoteName ? "_".$this->remoteName : ""); # FIXME move login into Account
    my $value    = {filepath => $filepath};
    if (-e $filepath) {
        $isFirstLogin = 0;
        $lastlog      = (stat(_))[9];
        osh_debug("is_account_nonexpired: got lastlog date: $lastlog");

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
        if (!chdir("/home/".$this->sysName)) {
            osh_debug("is_account_nonexpired: no exec access to the folder!");
            return R('ERR_NO_ACCESS', msg => "No read access to this account folder to compute last login time");
        }
        chdir($previousDir);
        $isFirstLogin = 1;

        # get the account creation timestamp as the lastlog
        $fnret = $this->getConfig('private/creation_timestamp');
        if ($fnret && $fnret->value) {
            $lastlog = $fnret->value;
            osh_debug("is_account_nonexpired: got creation date from config.creation_timestamp: $lastlog");
        }
        elsif (-e sprintf("/home/%s/accountCreate.comment", $this->sysName)) {

            # fall back to the stat of the accountCreate.comment file
            $lastlog = (stat(_))[9];
            osh_debug("is_account_nonexpired: got creation date from accountCreate.comment stat: $lastlog");
        }
        else {
            # last fall back to the stat of the ttyrec/ folder
            $lastlog = (stat(sprintf("/home/%s/ttyrec", $this->sysName)))[9];
            osh_debug("is_account_nonexpired: got creation date from ttyrec/ stat: $lastlog");
        }
    }

    my $seconds = time() - $lastlog;
    my $days    = int($seconds / 86400);
    $value->{'days'}                = $days;
    $value->{'seconds'}             = $seconds;
    $value->{'already_seen_before'} = !$isFirstLogin;
    osh_debug("Last account activity: $days days ago");

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
    my ($this, %params) = @_;
    my $nocache = $params{'nocache'};
    # FIXME check spurious args and warn

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

# checks that isExisting() and potentially other tiny things to ensure the account is sane
memoize('check');
sub check {
    my ($this, %params) = @_;

    $this->isExisting() or return;

    if (!-d $this->home) {
        return R('KO_INVALID_DIRECTORY', msg => "This account's home directory doesn't exist");
    }

    if (!-d $this->allowkeeperHome) {
        return R('KO_INVALID_DIRECTORY', msg => "This account's allowkeeper home directory doesn't exist");
    }

    return R('OK');
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

memoize('isSuperOwner');
sub isSuperOwner {
    my $this = shift;

    my $fnret = $this->isExisting();
    $fnret or return $fnret;

    my $superOwnerList = OVH::Bastion::config('adminAccounts')->value();
    if (any { $this->name eq $_ } @$superOwnerList) {
        if (OVH::Bastion::is_user_in_group(group => "osh-superowner", user => $this->name)) {
            return R('OK', msg => "Account ".$this->name." is a bastion superowner");
        }
    }
    return R('KO_ACCESS_DENIED', msg => "Account ".$this->name." is not a bastion superowner");
}

# return a hash with keys being the bastion group names and as values,
# a hash of relations to this account, i.e. member, guest, aclkeeper,
# gatekeeper, owner.
memoize('getGroups');
sub getGroups {
    my ($this, %params) = @_;
    my $cache = $params{'cache'}; # allow use of sys_getgr_all's cache
    my $fnret;

    $this->isExisting() or return;

    # we loop through all the system groups to find the ones having user
    # as a member (here, member of the group just means member of the system
    # group, this translate as either "member" or "guest" of the bastion group).
    # for the key* groups, member means aclkeeper, gatekeeper or owner of the
    # corresponding bastion group
    $fnret = OVH::Bastion::sys_getgr_all(cache => $cache);
    $fnret or return $fnret;

    my %result;
    foreach my $sysgroup (keys %{$fnret->value}) {
        # we must be a member of this sysgroup
        next if !(any { $this->sysName eq $_ } @{ $fnret->value->{$sysgroup}->{'members'} });

        ## no critic(RegularExpressions::ProhibitUnusedCapture) # false positive
        if ($sysgroup =~ /^key(?<groupname>.+?)(-(?<type>gatekeeper|aclkeeper|owner))?$/) {
            my $groupname = $+{'groupname'};
            my $type = $+{'type'};
            if (!$type) {
                # member or guest?
                my $prefix = $this->remoteName ? "allowed_".$this->remoteName : "allowed";
                if (-l sprintf("/home/allowkeeper/%s/%s.ip.%s", $this->sysName, $prefix, $groupname)) {
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
    my ($this, %params) = @_;
    my $plugin = $params{'plugin'};
    my $fnret;

    $this->isExisting() or return;

    if (!$plugin) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing mandatory param plugin");
    }

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
        my %canDo = (gatekeeper => 0, aclkeeper => 0, owner => 0);

        $fnret = $this->getGroups();
        $fnret or return $fnret;

        my %groups = %{$fnret->value};

        foreach my $type (qw{ aclkeeper gatekeeper owner }) {
            if (-f "$path_plugin/group-$type/$plugin") {

                # we can always execute these commands if we are a super owner
                my $canDo = !!$this->isSuperOwner()+0;

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
        if (OVH::Bastion::is_user_in_group(user => $this->sysName, group => "osh-$plugin", cache => 1)) {
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
