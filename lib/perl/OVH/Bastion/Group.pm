package OVH::Bastion::Group;
# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use common::sense;
use feature qw(switch);

use Hash::Util qw{ lock_hashref_recurse lock_ref_value unlock_ref_value };
use Fcntl;
use Memoize;
use Scalar::Util qw{ refaddr };
use List::Util qw{ none any };

use OVH::Bastion;
use OVH::Result;

use overload (
    '""' => 'name',
    'eq' => 'equals',
    'ne' => 'notEquals',
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
    # also clear the sys group cache
    OVH::Bastion::sys_clear_cache();
    return R('OK', value => $nbdeleted);
}

sub dbg {
    return 1 if (!$ENV{'OSH_DEBUG'} || $ENV{'PLUGIN_QUIET'});
    my ($this, $msg) = @_;

    my $exename = $0;
    $exename =~ s{.*/}{};
    print STDERR Term::ANSIColor::colored(sprintf("DBG:%s\[%d\] %s(%s[0x%x]): %s called by %s\n",
        $exename, $$, (caller(1))[3], $this?$this->name:'<u>',
        $this?refaddr($this):0, $msg, OVH::Bastion::call_stack(2)
    ), 'bold black');
    return 1;
}

sub newFromSysGroup {
    my ($objectType, $sysGroup, %p) = @_;
    $p{'sysGroup'} = $sysGroup;
    my $fnret = OVH::Bastion::check_args(\%p,
        mandatory => [qw{ sysGroup }],
        optionalFalseOk => [qw{ lax }],
        unknownOk => 1,
    );
    $fnret or return $fnret;

    if ($sysGroup =~ /^key([a-zA-Z0-9._-]+)$/) {
        my $middle = $1; # also untaint
        if ($middle =~ /-(gatekeeper|aclkeeper|owner)$/) {
            my $suffix = $1;
            if (!$p{'lax'}) {
                return R('ERR_INVALID_PARAMETER', msg => "The system group '$sysGroup' doesn't match a bastion group in non-lax mode");
            }
            $middle =~ s{\Q$suffix$}{};
        }
        delete $p{'sysGroup'};
        delete $p{'lax'};
        return __PACKAGE__->newFromName($middle, %p);
    }

    return R('ERR_INVALID_PARAMETER', msg => "The system group '$sysGroup' doesn't match a bastion group");
}

# cache the object returned by this func, as it's immutable anyway.
# if you want to refresh an object, use ->refresh, don't re-instanciate it,
# as you'll just get the same object thanks to memoize
#_memoizify('newFromName');
# => yep but not EXACTLY immutable, w.r.t isExisting and filling of undef fields!
# TODO global cache list of objects by name and serve that
sub newFromName {
    my ($objectType, $name, %p) = @_;
    $p{'name'} = $name;
    my $fnret = OVH::Bastion::check_args(\%p,
        mandatory => [qw{ name }],
        optionalFalseOk => [qw{ check }],
    );
    $fnret or return $fnret;

    if ($name =~ m/^([a-zA-Z0-9._-]+)$/) {
        $name = $1;    # untaint
    }
    else {
        return R('KO_FORBIDDEN_NAME', msg => 'Group name contains invalid characters');
    }

    if ($name =~ m/^key/i) {
        dbg(undef, "group name starts with key: $name");
        return R('KO_FORBIDDEN_PREFIX', msg => 'Forbidden prefix in group name');
    }
    if ($name =~ m/(keeper|owner|-tty)$/i) {
        return R('KO_FORBIDDEN_SUFFIX', msg => 'Forbidden suffix in group name');
    }
    elsif ($name =~ m/^[-.]/) {
        return R('KO_FORBIDDEN_PREFIX', msg => "Group name can't start with a '-' nor a '.'");
    }
    elsif (any { $name eq $_ } qw{ private root user self legacy osh }) {
        return R('KO_FORBIDDEN_NAME', msg => 'Forbidden group name');
    }
    # 18 max for the short group name, because 32 - length(key) - length(-gatekeeper) == 18
    elsif (length($name) > 18) {
        return R('KO_NAME_TOO_LONG', msg => "Group name is too long (limit is 18 chars)");
    }

    my $Group = {
        name            => $name,
        sysGroup        => "key$name",
        sysUser         => "key$name",
        sysGroupGatekeeper        => "key$name-gatekeeper",
        sysGroupAclkeeper        => "key$name-aclkeeper",
        sysGroupOwner        => "key$name-owner",
        keyHome       => "/home/keykeeper/key$name",
        home          => "/home/key$name",
        passwordHome  => "/home/key$name/pass",
        passwordFile  => "/home/key$name/pass/$name",
        allowedIpFile => "/home/key$name/allowed.ip",

        # a Group instance may or may not actually exist on the system, until
        # ->isExisting() is called. If the account does exist, said func will
        # set the following params:
        gid        => undef,
        members    => undef,

        # these will be filled on-demand by their getters:
        gatekeepers => undef,
        gatekeepersgid => undef,
        aclkeepers => undef,
        aclkeepersgid => undef,
        owners => undef,
        ownersgid => undef,
    };

    bless $Group, 'OVH::Bastion::Group';

    lock_hashref_recurse($Group);

    # have we been asked to check this group?
    if ($p{'check'}) {
        $fnret = $Group->check();
        $fnret or return $fnret;
    }

    return $Group;
}

BEGIN {
    no strict "refs";

    # simple getters, they have no corresponding setter, as Group objects are immutable
    foreach my $attr (qw{
            name sysGroup sysGroupGatekeeper sysGroupAclkeeper sysGroupOwner keyHome
            passwordFile allowedIpFile home sysUser passwordHome
        }) {
        *$attr = sub {
            my $this = shift;
            return $this->{$attr};
        };
    }

    # almost-simple getters, they just need to have a completely defined Group, hence
    # they ensure that ->isExisting has been called first (it is memoized, so only
    # expensive on the first call)
    foreach my $attr (qw{ gid }) {
        *$attr = sub {
            my $this = shift;
            if (!defined($this->{$attr})) {
                # check for groups's existence and fill $attr if it's the case
                $this->isExisting();
            }
            return $this->{$attr};
        };
    }

    use strict "refs";
}

sub equals {
    my ($this, $that) = @_;
    return (ref $this eq ref $that && $this->name eq $that->name);
}

sub notEquals {
    my ($this, $that) = @_;
    return !($this eq $that);
}

_memoizify('isExisting');
sub isExisting {
    my ($this, %p) = @_;
    my $fnret = OVH::Bastion::check_args(\%p,
    );
    $fnret or return $fnret;

    $fnret = OVH::Bastion::sys_getgr_name(name => $this->sysGroup);
    if (!$fnret)
    {
        return R('KO_GROUP_NOT_FOUND', msg => "The bastion group '".$this->name."' doesn't exist");
    }

    for my $key (qw{ gid members }) {
        unlock_ref_value($this, $key);
        $this->{$key} = $fnret->value->{$key};
        lock_ref_value($this, $key);
    }

    return R('OK');
}

# checks that isExisting() and potentially other tiny things to ensure the account is sane
_memoizify('check');
sub check {
    my ($this, %p) = @_;

    my $fnret = $this->isExisting();
    $fnret or return $fnret;

    if (!-d $this->home) {
        return R('KO_INVALID_DIRECTORY', msg => "This group's home directory doesn't exist");
    }

    if (!-d $this->keyHome) {
        return R('KO_INVALID_DIRECTORY', msg => "This group's key directory doesn't exist");
    }

    return R('OK');
}

# on-demand getters. we don't handle realm support accounts especially
# because remote accounts should never be owners, gatekeepers or aclkeepers
_memoizify('getOwners');
sub getOwners {
    my ($this, %p)     = @_;
    my $fnret = OVH::Bastion::check_args(\%p);
    $fnret or return $fnret;

    $fnret = $this->isExisting();
    $fnret or return $fnret;

    $fnret = OVH::Bastion::sys_getgr_name(name => $this->sysGroupOwner);
    $fnret or return $fnret;

    unlock_ref_value($this, $_) for qw{ owners ownersgid };
    $this->{'owners'} = $fnret->value->{'members'};
    $this->{'ownersgid'} = $fnret->value->{'gid'}+0;
    lock_ref_value($this, $_) for qw{ owners ownersgid };

    return R('OK', value => $this->{'owners'});
}

_memoizify('getGatekeepers');
sub getGatekeepers {
    my ($this, %p)     = @_;
    my $fnret = OVH::Bastion::check_args(\%p);
    $fnret or return $fnret;

    $fnret = $this->isExisting();
    $fnret or return $fnret;

    $fnret = OVH::Bastion::sys_getgr_name(name => $this->sysGroupGatekeeper);
    $fnret or return $fnret;

    unlock_ref_value($this, $_) for qw{ gatekeepers gatekeepersgid };
    $this->{'gatekeepers'} = $fnret->value->{'members'};
    $this->{'gatekeepersgid'} = $fnret->value->{'gid'}+0;
    lock_ref_value($this, $_) for qw{ gatekeepers gatekeepersgid };

    return R('OK', value => $this->{'gatekeepers'});
}

_memoizify('getAclkeepers');
sub getAclkeepers {
    my ($this, %p)     = @_;
    my $fnret = OVH::Bastion::check_args(\%p);
    $fnret or return $fnret;

    $fnret = $this->isExisting();
    $fnret or return $fnret;

    $fnret = OVH::Bastion::sys_getgr_name(name => $this->sysGroupAclkeeper);
    $fnret or return $fnret;

    unlock_ref_value($this, $_) for qw{ aclkeepers aclkeepersgid };
    $this->{'aclkeepers'} = $fnret->value->{'members'};
    $this->{'aclkeepersgid'} = $fnret->value->{'gid'}+0;
    lock_ref_value($this, $_) for qw{ aclkeepers aclkeepersgid };

    return R('OK', value => $this->{'aclkeepers'});
}

# we also handle realms (remote accounts) and we'll return their
# fully qualified names where applicable (realm/joe format)
_memoizify('getMembersOrGuests');
sub getMembersOrGuests {
    my ($this, %p)     = @_;
    my $fnret = OVH::Bastion::check_args(\%p,
        optionalFalseOk => [qw{ wantObjects }]
    );
    $fnret or return $fnret;

    $fnret = $this->isExisting();
    $fnret or return $fnret;

    $this->dbg("system member list of this group is: ".join(" ", @{ $this->{'members'} || [] }));

    my @list;
    foreach my $accountName (@{ $this->{'members'} || [] }) {
        next if $accountName eq 'allowkeeper';

        my $Account = OVH::Bastion::Account->newFromName($accountName, type => "account");
        if (!$Account) {
            OVH::Bastion::warn_syslog("Got an invalid account '$accountName' ($Account)");
            next;
        }

        $this->dbg("working on account ".$Account->name." of type ".$Account->type);

        if ($Account->type eq 'realm') {
            $fnret = $Account->getRemoteAccounts();
            if (!$fnret) {
                $this->dbg("getRemoteAccounts failed: $fnret");
                next;
            }

            foreach my $RemoteAccount (@{ $fnret->value || [] }) {
                push @list, ($p{'wantObjects'} ? $RemoteAccount : $RemoteAccount->name) if $RemoteAccount;
            }
        }
        else {
            push @list, ($p{'wantObjects'} ? $Account : $Account->name);
        }
    }

    return R('OK', value => \@list);
}

# actual bastion group members have a symlink to the group's allowed.ip
# in their own allowkeeper home.
# we also handle realms (remote accounts) and we'll return their
# fully qualified names where applicable (realm/joe format)
_memoizify('getMembers');
sub getMembers {
    my ($this, %p)     = @_;
    my $fnret = OVH::Bastion::check_args(\%p,
        optionalFalseOk => [qw{ wantObjects }]
    );
    $fnret or return $fnret;

    $fnret = $this->getMembersOrGuests(wantObjects => 1);
    $fnret or return $fnret;

    my @list;
    foreach my $Account (@{ $fnret->value }) {
        if ($this->hasMember($Account)) {
            push @list, ($p{'wantObjects'} ? $Account : $Account->name);
        }
    }
    return R('OK', value => \@list);
}

_memoizify('getGuests');
sub getGuests {
    my ($this, %p)     = @_;
    my $fnret = OVH::Bastion::check_args(\%p,
        optionalFalseOk => [qw{ wantObjects }]
    );
    $fnret or return $fnret;

    $fnret = $this->getMembersOrGuests(wantObjects => 1);
    $fnret or return $fnret;

    my @list;
    foreach my $Account (@{ $fnret->value }) {
        if ($this->hasGuest($Account)) {
            push @list, ($p{'wantObjects'} ? $Account : $Account->name);
        }
    }
    return R('OK', value => \@list);
}

# other funcs

_memoizify('getKeys');
sub getKeys {
    my ($this, %p)     = @_;
    my $fnret = OVH::Bastion::check_args(\%p,
        optionalFalseOk => [qw{ listOnly forceKey noexec }],
    );
    $fnret or return $fnret;

    $fnret = $this->check();
    $fnret or return $fnret;

    my $name = $this->name;
    $fnret = OVH::Bastion::get_pub_keys_from_directory(
        dir         => $this->keyHome,
        pattern     => qr/^id_([a-z0-9]+)_\Q$name\E/,
        listOnly    => $p{'listOnly'},
        forceKey    => $p{'forceKey'},
        noexec      => $p{'noexec'},
        wantPrivate => 1,
    );
    return $fnret;
}

_memoizify('sysGroupFromRole');
sub sysGroupFromRole {
    my ($this, $role, %p)     = @_;
    $p{'role'} = $role;
    my $fnret = OVH::Bastion::check_args(\%p,
        mandatory => [qw{ role }],
    );
    $fnret or return $fnret;

    # look for the proper sysgroup depending on the requested role
    my $sysGroupToCheck;
    given ($p{'role'}) {
        when (/^(member|guest|memberorguest)$/) { $sysGroupToCheck = $this->sysGroup; }
        when ("owner") { $sysGroupToCheck = $this->sysGroupOwner; }
        when ("aclkeeper") { $sysGroupToCheck = $this->sysGroupAclkeeper; }
        when ("gatekeeper") { $sysGroupToCheck = $this->sysGroupGatekeeper; }
        default { return R('ERR_INVALID_ARGUMENT', msg => "Unknown role '$p{'role'}'"); }
    }
    return R('OK', value => $sysGroupToCheck);
}

_memoizify('hasRole');
sub hasRole {
    my ($this, $Account, %p)     = @_;
    $p{'Account'} = $Account;
    my $fnret = OVH::Bastion::check_args(\%p,
        mandatory => [qw{ Account role }],
        optionalFalseOk => [qw{ superowner }],
    );
    $fnret or return $fnret;

    # superowner is not applicable to members or guests
    if (exists $p{'superowner'} && none { $p{'role'} eq $_ } qw{ owner aclkeeper gatekeeper }) {
        return R('ERR_INVALID_ARGUMENT', msg => "superowner is not supported for this role");
    }

    $fnret = $this->isExisting();
    $fnret or return $fnret;

    require OVH::Bastion::Account;
    $fnret = $Account->isExisting();
    $fnret or return $fnret;

    # look for the proper sysgroup depending on the requested role
    $fnret = $this->sysGroupFromRole($p{'role'});
    $fnret or return $fnret;

    my $sysGroupToCheck = $fnret->value;
    $fnret = OVH::Bastion::is_user_in_group(user => $Account->sysUser, group => $sysGroupToCheck);

    if (any { $p{'role'} eq $_ } qw{ owner aclkeeper gatekeeper }) {
        # for owner aclkeeper gatekeeper, membership of the system group is enough
        return R('OK', value => { superowner => 0 }) if $fnret;

        # otherwise, it also works if account is a superowner and superowner is allowed by our caller
        if ($p{'superowner'} && $Account->isSuperOwner) {
            return R('OK', value => { superowner => 1 });
        }

        # otherwise, game over
        return R('KO_NOT_GROUP_'.uc($p{'role'}),
            msg => "Account '$Account' doesn't have the '$p{'role'}' role on group '$this'");
    }

    # for member and guest, membership of the system group is always required
    return R('KO_NOT_GROUP_'.uc($p{'role'}),
        msg => "Account '$Account' is not a $p{'role'} of group '$this'") if !$fnret;

    if ((any { $p{'role'} eq $_ } qw{ member memberorguest }) && -l $Account->allowedMemberFile($this)) {
        # -l => test that file exists and is a symlink
        # -r => test that the symlink dest still exists => REMOVED, because we (the caller) might not have the right
        #       to read the file if we're not member or guest ourselves
        return R('OK');
    }
    elsif ((any { $p{'role'} eq $_ } qw{ guest memberorguest }) && -f $Account->allowedGuestFile($this)) {
        return R('OK');
    }

    return R('KO_NOT_GROUP_'.uc($p{'role'}), msg => "Account '$Account' is not a $p{'role'} of group '$this'");
}

sub hasOwner         { my ($this, $A, %p) = @_; $p{'role'} = "owner";         return $this->hasRole($A, %p); }
sub hasGatekeeper    { my ($this, $A, %p) = @_; $p{'role'} = "gatekeeper";    return $this->hasRole($A, %p); }
sub hasAclkeeper     { my ($this, $A, %p) = @_; $p{'role'} = "aclkeeper";     return $this->hasRole($A, %p); }
sub hasMemberOrGuest { my ($this, $A, %p) = @_; $p{'role'} = "memberorguest"; return $this->hasRole($A, %p); }
sub hasMember        { my ($this, $A, %p) = @_; $p{'role'} = "member";        return $this->hasRole($A, %p); }
sub hasGuest         { my ($this, $A, %p) = @_; $p{'role'} = "guest";         return $this->hasRole($A, %p); }

_memoizify('getConfig');
sub getConfig {
    my ($this, $key, %p) = @_;

    my $fnret = OVH::Bastion::check_args(\%p);
    $fnret or return $fnret;

    $fnret = $this->check();
    $fnret or return $fnret;

    if ($key =~ /^([a-zA-Z0-9_-]+)$/) {
        $key = $1; # untaint
    }
    else {
        return R('ERR_INVALID_PARAMETER', msg => "Invalid configuration key asked ($key)");
    }

    my $filename = $this->home."/$key.config";
    my $fh;
    if (!open($fh, '<', $filename)) {
        return R('ERR_CANNOT_OPEN_FILE', msg => "Error while trying to open file $filename for read ($!)");
    }
    my $getvalue = do { local $/ = undef; <$fh> };
    close($fh);
    return R('OK', value => $getvalue);
}

sub setConfig {
    my ($this, $key, $value, %p) = @_;

    my $fnret = OVH::Bastion::check_args(\%p);
    $fnret or return $fnret;

    if ($key =~ /^([a-zA-Z0-9_-]+)$/) {
        $key = $1; # untaint
    }
    else {
        return R('ERR_INVALID_PARAMETER', msg => "Invalid configuration key asked ($key)");
    }

    my $filename = $this->home."/$key.config";

    # be nice and delete the cache of getConfig
    if (delete $CACHE{refaddr($this)."!getConfig!$key"}) {
        $this->dbg("successfully deleted getConfig cache for $key");
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
    chown $this->gid, $this->gid, $filename;
    return R('OK');
}

sub deleteConfig {
    my ($this, $key, %p) = @_;

    my $fnret = OVH::Bastion::check_args(\%p);
    $fnret or return $fnret;

    $fnret = $this->check();
    $fnret or return $fnret;

    if ($key =~ /^([a-zA-Z0-9_-]+)$/) {
        $key = $1; # untaint
    }
    else {
        return R('ERR_INVALID_PARAMETER', msg => "Invalid configuration key asked ($key)");
    }

    my $filename = $this->home."/$key.config";

    # be nice and delete the cache of getConfig
    if (delete $CACHE{refaddr($this)."!getConfig!$key"}) {
        $this->dbg("successfully deleted getConfig cache for $key");
    }

    if (unlink($filename)) {
        return R('OK');
    }
    elsif ($! =~ /no such file/i) {
        return R('OK_NO_CHANGE');
    }
    else {
        return R('ERR_DELETION_FAILED', msg => "Couldn't delete $this config $key: $!");
    }
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

    return OVH::Bastion::ssh_test_access_to(Group => $this, ip => $p{'ip'}, port => $p{'port'}, user => $p{'user'});
}

1;
