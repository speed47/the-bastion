package OVH::Bastion::Account;
# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use common::sense;

use Cwd; # getcwd
use Fcntl;
use Hash::Util qw{ lock_hashref_recurse lock_ref_value unlock_ref_value };
use List::Util qw{ any none };
use Memoize;
use Scalar::Util qw{ refaddr };
use Term::ANSIColor;

use OVH::Bastion;
use OVH::Result;

use overload (
    '""' => 'name',
    'eq' => 'equal',
    'ne' => 'notEqual',
);

# we'll instruct memoize to use this hash,
# so we can properly flush it by-instance when we need it
my %CACHE;

# we also need to define our own normalizer so that the instance
# address is part of the hash key
sub _normalize {
    my ($func, $this, @args) = @_;
    my @x = (refaddr($this), $func);
    push @x, map { defined ? $_ : chr(29) } @args;
    return join("!", @x);
}

sub _memoizify {
    my $funcname = shift;
    return memoize(
        $funcname,
        SCALAR_CACHE => ['HASH' => \%CACHE],
        LIST_CACHE => ['HASH' => \%CACHE],
        NORMALIZER => sub { unshift @_, $funcname; goto \&_normalize; }
    );
}

# nullify all the cache for this instance, thanks to the
# fact that we know the instance address is part of all the
# cache keys for this instance
sub refresh {
    my $this = shift;
    my $addr = refaddr($this);
    my $nbdeleted = 0;
    foreach my $key (keys %CACHE) {
        if ($key =~ /^\Q$addr!/) {
            delete $CACHE{$key};
            $nbdeleted++;
        }
    }
    return R('OK', value => $nbdeleted);
}

sub newFromEnv {
    my ($this, %p) = @_;
    return $this->newFromName(OVH::Bastion::get_user_from_env()->value, %p);
}

_memoizify('newLocalRoot');
sub newLocalRoot {
    my ($this, %p) = @_;
    $p{'isFake'} = 1; # FIXME do we use isFake for anything else that localRoot? if not, do we need it?
    return $this->newFromName('<root>', %p);
}

# $name can be "joe" or "realm/joe"
sub newFromName {
    my ($objectType, $name, %p) = @_;
    $p{'name'} = $name;
    my $fnret = OVH::Bastion::check_args(\%p,
        mandatory => [qw{ name }],
        optional => [qw{ type check }],
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
        if ($p{'type'} eq 'localRoot') {
            $Account->{'type'} = 'localRoot';
        }
        # FIXME else: type undef? meh, is isFake==localRoot? (see FIXME above)
    }
    else {
        # FIXME it means we can't newFromName() an account that is INVALID but EXISTING. is this a problem?
        $fnret = _new_from_name(name => $p{'name'}, type => $p{'type'} || 'regular');
        $fnret or return $fnret;
        # we have either:
        # {type => "local",  sysaccount => $1,         realm => undef, remoteaccount => undef, account => $1}
        # {type => "realm",  sysaccount => "realm_$1", realm => $1,    remoteaccount => undef, account => $1}
        # {type => "remote", sysaccount => "realm_$1", realm => $1,    remoteaccount => $2,    account => "$1/$2"}

        my $sysaccount = $fnret->value->{'sysaccount'};
        my $allowedPrefix = ($fnret->value->{'remoteaccount'} ? 'allowed_'.$fnret->value->{'remoteaccount'} : 'allowed');
        $Account = {
            # main account attributes
            name            => $fnret->value->{'account'},           # joe   or acme/joe
            sysUser         => $fnret->value->{'sysaccount'},        # joe   or realm_acme
            remoteName      => $fnret->value->{'remoteaccount'},     # undef or joe
            realm           => $fnret->value->{'realm'},             # undef or acme
            type            => $fnret->value->{'type'},              # local|remote|realm|localRoot
            isFake          => 0,

            ttyGroup        => "$sysaccount-tty",

            # folder and file locations related to this account
            home                 => "/home/$sysaccount", # isExisting() will yell if /etc/passwd disagrees
            allowkeeperHome      => "/home/allowkeeper/$sysaccount",
            allowedIpFile        => "/home/allowkeeper/$sysaccount/$allowedPrefix.ip",
            allowedPrivateFile   => "/home/allowkeeper/$sysaccount/$allowedPrefix.private",
            allowedGuestFile     => "/home/allowkeeper/$sysaccount/$allowedPrefix.partial.#GROUP#",
            allowedMemberFile    => "/home/allowkeeper/$sysaccount/$allowedPrefix.ip.#GROUP#",
            passwordHome             => "/home/$sysaccount/pass",
            passwordFile         => "/home/$sysaccount/pass/$sysaccount",

            sshHome              => "/home/$sysaccount/.ssh",
            ttyrecHome           => "/home/$sysaccount/ttyrec",
            authorizedKeysFile   => "/home/$sysaccount/.ssh/authorized_keys2",
            sshConfigFile        => "/home/$sysaccount/.ssh/config",

            # an Account instance may or may not actually exist on the system, until
            # ->isExisting() is called. If the account does exist, said func will
            # set the following params:
            uid        => undef,
            gid        => undef,
        };
    }

    bless $Account, 'OVH::Bastion::Account';

    lock_hashref_recurse($Account);

    # have we been asked to check this account?
    if ($p{'check'}) {
        $fnret = $Account->check();
        $fnret or return $fnret;
    }

    return $Account;
}

BEGIN {
    no strict "refs";

    # simple getters, they have no corresponding setter, as Account objects are immutable
    foreach my $attr (qw{
            name sysUser remoteName realm type home allowkeeperHome
            passwordHome sshHome ttyrecHome passwordFile
            sshConfigFile authorizedKeysFile isFake ttyGroup
        }) {
        *$attr = sub {
            my $this = shift;
            return $this->{$attr};
        };
    }

    # simple getters that make no sense for specific account types, in which case we log a warning
    # when they're called, and return undef
    foreach my $attr (qw{ allowedIpFile allowedPrivateFile }) {
        *$attr = sub {
            my ($this, %p) = shift;
            if (none { $this->type eq $_ } qw{ local remote }) {
                OVH::Bastion::warn_syslog("Attempted to access attribute '$attr' on '$this' "
                    . "which is of type ".$this->type);
                return;
            }
            return $this->{$attr};
        };
    }

    # almost-simple getters, they just need to have a completely defined Account, hence
    # they ensure that ->isExisting has been called first (it is memoized, so only
    # expensive on the first call)
    foreach my $attr (qw{ uid gid }) {
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

# more complicated getter
#_memoizify('allowedGuestFile');
sub allowedGuestFile {
    my ($this, $Group, %p) = @_;
    $p{'Group'} = $Group;
    my $fnret = OVH::Bastion::check_args(\%p,
        mandatory => [qw{ Group }],
    );
    if (!$fnret) {
        warn_syslog("Called allowedGuestFile with bad params");
        return '/dev/invalid/file'; 
    }

    # we don't call check() or isExisting() on the group, as it doesn't actually
    # need to exist, we'll still return the valid theoretical path

    my $path = $this->{'allowedGuestFile'};
    my $groupName = $Group->name;
    $path =~ s{#GROUP#}{$groupName}g;
    return $path;
}

_memoizify('allowedMemberFile');
sub allowedMemberFile {
    my ($this, $Group, %p) = @_;
    $p{'Group'} = $Group;
    my $fnret = OVH::Bastion::check_args(\%p,
        mandatory => [qw{ Group }],
    );
    if (!$fnret) {
        warn_syslog("Called allowedMemberFile with bad params");
        return '/dev/invalid/file'; 
    }

    # we don't call check() or isExisting() on the group, as it doesn't actually
    # need to exist, we'll still return the valid theoretical path

    my $path = $this->{'allowedMemberFile'};
    my $groupName = $Group->name;
    $path =~ s{#GROUP#}{$groupName}g;
    return $path;
}

sub equal {
    my ($this, $that) = @_;
    return (ref $this eq ref $that && $this->name eq $that->name);
}

sub notEqual {
    my ($this, $that) = @_;
    return !($this eq $that);
}

# do NOT memoize this, as we're checking envvars and $<
sub isLocalRoot {
    my ($this, %p) = @_;
    return R($this->isFake && $this->name eq '<root>' ? 'OK' : 'KO');
}

sub _config_file_from_composite_key {
    my ($this, $compositeKey) = @_;

    my ($type, $key) = $compositeKey =~ m{^(private|public)/([a-zA-Z0-9_-]+)$};
    if (!$type || !$key) {
        return R('ERR_INVALID_PARAMETER', msg => "Invalid configuration key asked ($compositeKey)");
    }

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

    return R('OK', value => { filename => $filename, type => $type });
}

_memoizify('getConfig');
sub getConfig {
    my ($this, $compositeKey, %p) = @_;

    my $fnret = OVH::Bastion::check_args(\%p);
    $fnret or return $fnret;

    $fnret = $this->check();
    $fnret or return $fnret;

    $fnret = $this->_config_file_from_composite_key($compositeKey);
    $fnret or return $fnret;

    my $filename = $fnret->value->{'filename'};
    my $fh;
    if (!open($fh, '<', $filename)) {
        return R('ERR_CANNOT_OPEN_FILE', msg => "Error while trying to open file $filename for read ($!)");
    }
    my $getvalue = do { local $/ = undef; <$fh> };
    close($fh);
    return R('OK', value => $getvalue);
}

sub setConfig {
    my ($this, $compositeKey, $value, %p) = @_;

    my $fnret = OVH::Bastion::check_args(\%p);
    $fnret or return $fnret;

    $fnret = $this->_config_file_from_composite_key($compositeKey);
    $fnret or return $fnret;

    my $filename = $fnret->value->{'filename'};
    my $type = $fnret->value->{'type'};

    # be nice and delete the cache of getConfig
    if (delete $CACHE{refaddr($this)."!getConfig!$compositeKey"}) {
        OVH::Bastion::osh_debug("Account::setConfig($this): successfully deleted getConfig cache for $compositeKey");
    }

    unlink($filename);    # remove any previous value
    my $fh;
    # sysopen: avoid symlink attacks
    if (!sysopen($fh, $filename, O_RDWR | O_CREAT | O_EXCL)) {
        return R('ERR_CANNOT_OPEN_FILE', msg => "Error while trying to open file $filename for write ($!)");
    }
    print $fh $value;
    close($fh);
    chmod 0644, $filename;

    if ($type eq 'public') {
        # need to chown to allowkeeper:allowkeeper
        my (undef, undef, $allowkeeperuid, $allowkeepergid) = getpwnam("allowkeeper");
        chown $allowkeeperuid, $allowkeepergid, $filename;
    }
    return R('OK');
}

sub deleteConfig {
    my ($this, $compositeKey, %p) = @_;

    my $fnret = OVH::Bastion::check_args(\%p);
    $fnret or return $fnret;

    $fnret = $this->check();
    $fnret or return $fnret;

    $fnret = $this->_config_file_from_composite_key($compositeKey);
    $fnret or return $fnret;

    # be nice and delete the cache of getConfig
    delete $CACHE{refaddr($this)."!getConfig!$compositeKey"};

    my $filename = $fnret->value->{'filename'};
    if (unlink($filename)) {
        return R('OK');
    }
    elsif ($! =~ /no such file/i) {
        return R('OK_NO_CHANGE');
    }
    else {
        return R('ERR_DELETION_FAILED', msg => "Couldn't delete $this config $compositeKey: $!");
    }
}

_memoizify('isActive');
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

_memoizify('isTTLNotExpired');
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

_memoizify('isNotExpired');
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
    my $value    = {filepath => $filepath, info => undef};
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

_memoizify('isExisting');
sub isExisting {
    my ($this, %p) = @_;
    my $fnret = OVH::Bastion::check_args(\%p,
        optionalFalseOk => [qw{ ignoreConfig }],
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
        $fnret = OVH::Bastion::sys_getpw_name(name => $this->sysUser);
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
            return R('ERR_NOT_BASTION_ACCOUNT', msg => sprintf("Account '%s' is not a bastion account", $this->name));
        }

        my ($newdir) = $entry{'home'} =~ m{([/a-zA-Z0-9._-]+)};                   # untaint
        if ($newdir ne $entry{'home'}) {
            return R('ERR_SECURITY_VIOLATION', msg => "Forbidden characters in account home directory")
        }
        $entry{'home'} = $newdir;

        if ($entry{'home'} ne $this->home) {
            OVH::Bastion::warn_syslog(sprintf("Account %s home is '%s' instead of '%s'", $this->name, $entry{'home'}, $this->home));
            return R('ERR_SECURITY_VIOLATION', msg => "Mismatch between theoretical and actual home location");
        }

        if (!getgrnam($this->ttyGroup)) {
            OVH::Bastion::warn_syslog(sprintf("The tty group '%s' of account '%s' doesn't exist", $this->ttyGroup, $this->name));
            return R('ERR_MISSING_TTY_GROUP', msg => "The tty group of this account doesn't exist");
        }

        if ($entry{'uid'} != $entry{'gid'}) {
            OVH::Bastion::warn_syslog(sprintf("Account '%s' has mismatching UID (%d) and GID (%d)", $this->name, $entry{'uid'}, $entry{'gid'}));
            return R('ERR_SECURITY_VIOLATION', msg => "Mismatch between UID and GID");
        }

        if (!$p{'ignoreConfig'}) {
            # don't check for is_valid_uid if we have the ignoreConfig flag passed, as it means that the
            # caller is currently loading and validating the configuration, and calling us to achieve that,
            # so we can't use it to validate our own data, or we get a double-recursive loop
            $fnret = OVH::Bastion::is_valid_uid(uid => $entry{'uid'}, type => 'user');
            if (!$fnret) {
                OVH::Bastion::warn_syslog(sprintf("Account '%s' has an invalid UID (%d): %s", $this->name, $entry{'uid'}, $fnret->msg));
                return R('ERR_SECURITY_VIOLATION', msg => "Invalid UID for account");
            }
        }

        foreach my $key (qw{ uid gid }) {
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
    if ($this->isLocalRoot) {
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
                "Mismatching SUDO_USER envvar '%s' while checking account '%s' with sysUser '%s'",
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
_memoizify('check');
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
    my $type = $p{'type'};
    # - local: disallow realm-formatted accounts aka $realm/$remoteself
    # - remote: allow only realm-formatted accounts aka $realm/$remoteself
    # - regular: either a local or remote account (autodetect and allow both)
    # - realm: a realm support account, must start with realm_*
    # - account: either a local, or realm support account (autodetect and allow both)
    # - incoming: either a local account or a realm account, in which case we'll autodetect
    #             the remote account (through LC_BASTION) and setup accordingly. If we don't find a remote account
    #             and we have a realm account, deny it (return an error). Mainly used to create an Account instance
    #             from an ingress connection information.
    # - group: system user with the same uid than a bastion group's gid, must start with key*
    #        FIXME: type=group is actually not an ::Account and shouldn't be there

    # if both types are allowed, resolve whether it looks like a local or remote account
    # so that the proper tests are done in the rest of the func
    if ($type eq 'regular') {
        $type = ($name =~ m{/} ? 'remote' : 'local');
    }
    elsif ($type eq 'account') {
        $type = ($name =~ /^realm_/ ? 'realm' : 'local');
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
    elsif (any { $name eq $_ } qw{ root proxyhttp keykeeper passkeeper logkeeper realm realm_realm }) {
        #OVH::Bastion::warn_syslog("Attempting to instanciate an account with name=$name from ".OVH::Bastion::call_stack());
        return R('KO_FORBIDDEN_NAME', msg => "$whatis name '$name' is reserved");
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
        return R('OK', value => {
            sysaccount => "realm_$1",
            realm => $1,
            remoteaccount => $2,
            account => "$1/$2",
            type => 'remote'
        });
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

        my ($realmName) = $name =~ /^realm_(.+)/;
        return R('OK', value => {
            sysaccount => $name,
            realm => $realmName, # undef if name !~ /^realm_/
            remoteaccount => undef,
            account => $name,
            type => ($realmName ? 'realm' : 'local'),
        });
    }
    else {
        return R('KO_FORBIDDEN_CHARS', msg => "$whatis name '$name' contains forbidden characters");
    }
    return R('ERR_IMPOSSIBLE_CASE');
}

_memoizify('hasRole');
sub hasRole {
    my ($this, $role) = @_;

    my $fnret = $this->isExisting();
    $fnret or return $fnret;

    if (OVH::Bastion::is_user_in_group(group => "osh-$role", user => $this->sysUser)) {
            return R('OK', msg => "Account '$this' has the bastion role '$role'");
    }

    return R('KO_ACCESS_DENIED', msg => "Account $this doesn't have the role '$role'");
}

# used by isAdmin and isSuperOwner
sub _has_special_role {
    my ($this, $role, $configList, $sysGroup) = @_;

    my $fnret = $this->isExisting();
    $fnret or return $fnret;

    if (OVH::Bastion::is_user_in_group(group => $sysGroup, user => $this->sysUser)) {
        if (!$configList || any { $this->name eq $_ } @{ OVH::Bastion::config($configList)->value || [] }) {
            return R('OK', msg => "Account '$this' has the bastion role '$role'");
        }
    }
    return R('KO_ACCESS_DENIED', msg => "Account $this doesn't have the role '$role'");
}


_memoizify('isAdmin');
sub isAdmin      { my $this = shift; return $this->_has_special_role("administrator", "adminAccounts", "osh-admin"); }
_memoizify('isSuperOwner');
sub isSuperOwner { my $this = shift; return $this->_has_special_role("superowner", "superOwnerAccounts", "osh-superowner") || $this->isAdmin; }
sub isAuditor    { my $this = shift; return $this->hasRole("auditor"); }

# return a hash with keys being the bastion group names and as values,
# a hash of relations to this account, i.e. member, guest, aclkeeper,
# gatekeeper, owner.
_memoizify('getGroups');
sub getGroups {
    my ($this, %p) = @_;
    my $fnret = OVH::Bastion::check_args(\%p,
        optional => [qw{ roles }]
    );
    $fnret or return $fnret;

    $fnret = $this->isExisting();
    $fnret or return $fnret;

    # first, get a list of all the bastion groups
    $fnret = OVH::Bastion::get_group_list(fast => 1);
    $fnret or return $fnret;
    my %groups = %{ $fnret->value || {} };

    # if no roles specified, return all of them
    my $roles = $p{'roles'} || [qw{ guest member owner aclkeeper gatekeeper }];

    my %result;
    foreach my $Group (values %groups) {
        foreach my $role (@$roles) {
            if ($Group->hasRole($this, role => $role)) {
                $result{$Group->name}{$role} = 1;
            }
        }
    }
    return R('OK', value => \%result);
}

_memoizify('canExecutePlugin');
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
                $canDo++ if (any { exists($_->{$type}) && $_->{$type} } values %groups);

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
        if (OVH::Bastion::is_user_in_group(user => $this->sysUser, group => "osh-$plugin")) {
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

_memoizify('getPersonalKeys');
sub getPersonalKeys {
    my ($this, %p) = @_;
    my $fnret = OVH::Bastion::check_args(\%p,
        optionalFalseOk => [qw{ forceKey listOnly noexec }],
    );
    $fnret or return $fnret;

    $fnret = $this->isExisting();
    $fnret or return $fnret;

    return OVH::Bastion::get_pub_keys_from_directory(
        dir         => $this->sshHome,
        pattern     => qr/^private\.pub$|^id_[a-z0-9]+[_.]private\.\d+\.pub$/,
        listOnly    => $p{'listOnly'} ? 1 : 0, # don't be slow and don't parse the keys (by calling ssh-keygen -lf)
        forceKey    => $p{'forceKey'},
        wantPrivate => 1,
        noexec      => $p{'noexec'} ? 1 : 0,
    );
}

sub setSshConfig {
    my ($this, %p) = @_;
    my $fnret = OVH::Bastion::check_args(\%p,
        mandatory => [qw{ key }],
        mandatoryFalseOk => [qw{ value }], # if value is undef, remove $key
    );
    $fnret or return $fnret;

    $fnret = $this->isExisting();
    $fnret or return $fnret;

    my $key = lc($p{'key'});

    # read file content
    $fnret = $this->getSshConfig();
    $fnret or return $fnret;
    my %keys = %{$fnret->value()};

    # remove key if it already exists
    delete $keys{$key};

    # add new key+value
    $keys{$key} = $p{'value'} if defined $p{'value'};

    # write modified file. to avoid symlink attacks, remove it then reopen it with sysopen()
    unlink($this->sshConfigFile);
    if (sysopen(my $sshconfig_fd, $this->sshConfigFile, O_RDWR | O_CREAT | O_EXCL)) {
        foreach my $keyWrite (sort keys %keys) {
            print $sshconfig_fd $keyWrite . " " . $keys{$keyWrite} . "\n";
        }
        close($sshconfig_fd);
    }
    else {
        return R('ERR_CANNOT_OPEN_FILE', msg => "Couldn't open ssh config file for write: $!");
    }

    # ensure file is readable by everyone (and mainly the account itself)
    if (!chmod 0644, $this->sshConfigFile) {
        return R('ERR_CANNOT_CHMOD', msg => "Couldn't ensure the ssh config file perms are correct");
    }

    return R('OK');
}

sub getSshConfig {
    my ($this, %p) = @_;

    my $fnret = $this->isExisting();
    $fnret or return $fnret;

    # read file content. If it doesn't exist, not a problem
    my $sshconfig_data;
    if (open(my $sshconfig_fd, '<', $this->sshConfigFile)) {
        local $/ = undef;
        $sshconfig_data = <$sshconfig_fd>;
        close($sshconfig_fd);

        # ensure we don't have any Host or Match directive.
        # If we do, bail out: the file has been modified manually by someone
        if ($sshconfig_data =~ /^\s*(Host|Match)\s/mi) {
            return R('ERR_FILE_LOCALLY_MODIFIED',
                msg => "The ssh configuration of this account has been modified manually. "
                    ." As we can't guarantee modifying it won't cause adverse effects, modification aborted."
            );
        }

        # remove empty lines & comments
        my @lines = grep { /./ && !/^\s*#/ } split(/\n/, $sshconfig_data);

        # lowercase all keys
        my %keys = map { m/^(\S+)\s+(.+)$/ ? (lc($1) => $2) : () } @lines;

        return R('OK_EMPTY') if !%keys;
        return R('OK', value => \%keys);
    }

    return R($! =~ /permission|denied/i ? 'ERR_ACCESS_DENIED' : 'OK_EMPTY');
}

# return the effective PIV ingress keys policy for this account,
# can be either enabled or disabled, depending on 3 config params,
# ingressRequirePIV (global setting), the account's own potential
# ingress PIV policy and the potential account grace period, both
# set by accountPIV
sub isPivPolicyEffectivelyEnabled {
    my ($this, %p)  = @_;

    my $fnret = $this->isExisting();
    $fnret or return $fnret;

    my $accountPolicy;
    $fnret = $this->getConfig("public/ingress_piv_policy");
    if (!$fnret) {

        # if file is not found, it means the account PIV policy is the default one.
        # this is the same as having its config set explicitly to 'default'
        $accountPolicy = 'default';
    }
    else {
        $accountPolicy = $fnret->value;

        # previously, 'enforce' was stored as 'yes'
        $accountPolicy = 'enforce' if $accountPolicy eq 'yes';
    }

    # if account policy is set to never, then the global policy doesn't matter
    return R('KO_DISABLED') if $accountPolicy eq 'never';

    # if account is currently in a non-expired grace period, then the global policy doesn't matter either
    $fnret = $this->getConfig("public/ingress_piv_grace");
    my $expiry = $fnret->value || 0;
    my $human  = OVH::Bastion::duration2human(seconds => ($expiry - time()))->value;
    return R('KO_DISABLED', msg => "$this is still in grace period for " . $human->{'human'}) if (time() < $expiry);

    # if account is set to enforce, and it's not in grace (handled above), then it's enabled
    return R('OK_ENABLED', msg => "$this policy is set to enforce") if $accountPolicy eq 'enforce';

    # otherwise the global policy applies
    return OVH::Bastion::config('ingressRequirePIV')->value()
      ? R('OK_ENABLED',  msg => "inherits the globally enabled policy")
      : R('KO_DISABLED', msg => "inherits the globally disabled policy");
}

sub accessModify {
    my ($this, %p) = @_;
    my $fnret = OVH::Bastion::check_args(\%p,
        # action: add or del
        # ip: can be a single ip or prefix
        # way: group, groupguest, personal
        mandatory => [qw{ action ip way }],
        # user: if undef, means a user-wildcard access
        # port: if undef, means a port-wildcard access
        optionalFalseOk => [qw{ user port comment forceKey forcePassword ttl }],
        # group: only for way=group or way=groupguest
        optional => [qw{ Group }],
    );
    $fnret or return $fnret;

    $fnret = $this->isExisting();
    $fnret or return $fnret;

    return OVH::Bastion::access_modify(Account => $this, %p);
}

sub generateEgressKey {
    my ($this, %p) = @_;
    my $fnret = OVH::Bastion::check_args(\%p,
        mandatory => [qw{ algo size }],
        optionalFalseOk => [qw{ passphrase }],
    );
    $fnret or return $fnret;

    $fnret = $this->isExisting();
    $fnret or return $fnret;

    require OVH::Bastion::Key;
    my $Key = OVH::Bastion::Key->newFromKeygen(
        way => 'egress',
        folder => $this->sshHome,
        prefix => 'private',
        name => $this->sysUser,
        algo       => $p{'algo'},
        size       => $p{'size'},
        passphrase => $p{'passphrase'},
    );
    return $Key;
}

_memoizify('getRealmSupportAccount');
# only for remote accounts
sub getRealmSupportAccount {
    my $this = shift;

    my $fnret = $this->isExisting();
    $fnret or return $fnret;

    if ($this->type ne 'remote') {
        return R('ERR_NOT_REMOTE_ACCOUNT', msg => "Can't get the realm support account for a non-remote account");
    }
    return __PACKAGE__->newFromName("realm_".$this->realm, type => "realm");
}

# only for realm support accounts, we return a list of Accounts (objects)
# that will all have their name in the format realmName/accountName,
# and of type==remote
_memoizify('getRemoteAccounts');
sub getRemoteAccounts {
    my $this = shift;

    my $fnret = $this->isExisting();
    $fnret or return $fnret;

    if ($this->type ne 'realm') {
        return R('ERR_NOT_REALM_SUPPORT_ACCOUNT', msg => "Can't get the remote accounts list for non-realm accounts");
    }

    my %accounts;
    if (opendir(my $dh, $this->allowkeeperHome)) {
        while (my $filename = readdir($dh)) {
            if ($filename =~ /allowed_([a-zA-Z0-9._-]+)\.(ip|partial|private)/) {
                $accounts{$1} = 1;
            }
        }
        closedir($dh);
    }

    my @list;
    foreach my $account (keys %accounts) {
        my $RemoteAccount = OVH::Bastion::Account->newFromName(
            sprintf("%s/%s", $this->realm, $account), type => "remote"
        );
        if (!$RemoteAccount) {
            OVH::Bastion::warn_syslog("Got an invalid remote account '$account' ($RemoteAccount)");
        }
        else {
            push @list, $RemoteAccount;
        }
    }

    return R('OK', value => \@list);
}

sub getAllAcls {
    my ($this, %p) = @_;
    my $fnret = OVH::Bastion::check_args(\%p,
    );
    $fnret or return $fnret;

    my @acls;
    require Data::Dumper;

    $fnret = $this->check();
    $fnret or return $fnret;

    # 1/3 check for personal accesses
    # ... normal way
    my $grantedPersonal = OVH::Bastion::get_acl_way(way => 'personal', account => $this->name);
    OVH::Bastion::osh_debug("get_acls: grantedPersonal=" . Data::Dumper::Dumper($grantedPersonal));
    push @acls, {type => 'personal', acl => $grantedPersonal->value}
      if ($grantedPersonal && @{$grantedPersonal->value});

    # ... legacy way
    my $grantedLegacy = OVH::Bastion::get_acl_way(way => 'legacy', account => $this->name);
    OVH::Bastion::osh_debug("get_acls: grantedLegacy=" . Data::Dumper::Dumper($grantedLegacy));
    push @acls, {type => 'personal-legacy', acl => $grantedLegacy->value}
      if ($grantedLegacy && @{$grantedLegacy->value});

    # 2/3 check groups
    $fnret = $this->getGroups(roles => [qw{ member guest }]);
    $fnret or return $fnret;

    my %groups = %{$fnret->value || {}};
    OVH::Bastion::osh_debug("get_acls: get_user_groups of $this says "
          . $fnret->msg
          . " with grouplist "
          . Data::Dumper::Dumper($fnret->value));

    foreach my $group (keys %{$fnret->value || {}}) {
        # instanciate and check the group
        my $Group = OVH::Bastion::Group->newFromName($group, check => 1);
        $Group or next;

        # then check for group access
        my $grantedGroup = OVH::Bastion::get_acl_way(way => "group", group => $Group->name);
        OVH::Bastion::osh_debug("get_acls: grantedGroup($Group)=" . Data::Dumper::Dumper($grantedGroup));

        # if group doesn't have access, don't even check legacy either
        next if not $grantedGroup;

        # now we have to cases, if the group has access: either the account is member or guest
        if ($groups{$group}{'member'}) {

            # normal member case, just reuse $grantedGroup
            OVH::Bastion::osh_debug("get_acls: adding grantedGroup to grants because is member");
            push @acls, {type => 'group-member', group => $group, acl => $grantedGroup->value}
              if ($grantedGroup && @{$grantedGroup->value});
        }
        elsif ($groups{$group}{'guest'}) {
            # normal guest case
            my $grantedGuest =
              OVH::Bastion::get_acl_way(way => "groupguest", group => $Group->name, account => $this->name);
            OVH::Bastion::osh_debug("get_acls: grantedGuest=" . Data::Dumper::Dumper($grantedGuest));

            # the guy must have a guest access but the group itself must also still have access
            if ($grantedGuest && $grantedGroup) {
                OVH::Bastion::osh_debug("get_acls: adding grantedGuest to grants because is guest and group has access");
                push @acls, {type => 'group-guest', group => $Group->name, acl => $grantedGuest->value}
                  if @{$grantedGuest->value};
            }

            # special legacy case; we also check if account has a legacy access for ip AND that the group ALSO has access to this ip
            if ($grantedLegacy && $grantedGroup) {
                OVH::Bastion::osh_debug("get_acls: adding grantedLegacy to grants because legacy not null and group has access");
                push @acls, {type => 'group-guest-legacy', group => $Group->name, acl => $grantedLegacy->value}
                  if @{$grantedLegacy->value};
            }
        }
        else {
            # should not happen
            OVH::Bastion::warn_syslog("get_acls: $this is in group $Group but is neither member or guest !!?");
        }
    }
    return R('OK', value => \@acls);
}

sub TO_JSON {
    my $this = shift;
    return $this->name;
}

sub sshTestAccessTo {
    my %params  = @_;
    my ($this, %p)     = @_;
    my $fnret = OVH::Bastion::check_args(\%p,
        mandatory => [qw{ ip }],
        optionalFalseOk => [qw{ port user forceKey forcePassword }], # FIXME force* unused
    );
    $fnret or return $fnret;

    return OVH::Bastion::ssh_test_access_to(Account=> $this, ip => $p{'ip'}, port => $p{'port'}, user => $p{'user'});
}

1;
