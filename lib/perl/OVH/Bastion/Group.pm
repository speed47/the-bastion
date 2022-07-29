package OVH::Bastion::Group;
use common::sense;

use Hash::Util qw{ lock_hashref_recurse lock_ref_value unlock_ref_value };
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
        LIST_CACHE => 'FAULT',
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
        sysGroupGatekeeper        => "key$name-gatekeeper",
        sysGroupAclkeeper        => "key$name-aclkeeper",
        sysGroupOwner        => "key$name-owner",
        keyHome    => "/home/keykeeper/key$name",
        passwordFile => "/home/key$name/pass/$name",
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
            passwordFile allowedIpFile
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

    my @list;
    foreach my $accountName (@{ $this->{'members'} || [] }) {
        next if $accountName eq 'allowkeeper';

        my $Account = OVH::Bastion::Account->newFromName($accountName, type => "account");
        $Account or next;

        if ($Account->type eq 'realm') {
            $fnret = $Account->getRemoteAccountsNames();
            $fnret or next;

            foreach my $remoteAccountName (@{ $fnret->value || [] }) {
                my $RemoteAccount = OVH::Bastion::Account->newFromName($remoteAccountName, type => "remote");
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

# don't memoize these funcs, as we already have proper cache (including invalidation) on the system group fetching
# mechanics, and those are the slower pieces of code due to filesystem access
sub hasOwner {
    my ($this, $Account, %p)     = @_;
    $p{'Account'} = $Account;
    my $fnret = OVH::Bastion::check_args(\%p,
        mandatory => [qw{ Account }],
        optionalFalseOk => [qw{ superowner }],
    );
    $fnret or return $fnret;

    $fnret = $this->isExisting();
    $fnret or return $fnret;

    require OVH::Bastion::Account;
    $fnret = $Account->isExisting();
    $fnret or return $fnret;

    $fnret = OVH::Bastion::is_user_in_group(user => $Account->sysUser, group => $this->sysGroupOwner);
    return R('OK', value => { superowner => 0 }) if $fnret;

    # if superowner allowed, try it
    if ($p{'superowner'} && $Account->isSuperOwner) {
        osh_debug("is <".$Account->name."> owner of <".$this->name."> ? => no but superowner so YES!");
        return R('OK', value => { superowner => 1 });
    }

    return R('KO_NOT_GROUP_OWNER', msg => "Account '".$Account->name."' is not an owner of group '".$this->name."'");
}

sub hasGatekeeper {
    my ($this, $Account, %p)     = @_;
    $p{'Account'} = $Account;
    my $fnret = OVH::Bastion::check_args(\%p,
        mandatory => [qw{ Account }],
    );
    $fnret or return $fnret;

    $fnret = $this->isExisting();
    $fnret or return $fnret;

    require OVH::Bastion::Account;
    $fnret = $Account->isExisting();
    $fnret or return $fnret;

    $fnret = OVH::Bastion::is_user_in_group(user => $Account->sysUser, group => $this->sysGroupGatekeeper);
    return $fnret if $fnret->is_err;
    return R('OK') if $fnret;
    return R('KO_NOT_GROUP_GATEKEEPER', msg => "Account '".$Account->name."' is not a gatekeeper of group '".$this->name."'");
}

sub hasAclkeeper {
    my ($this, $Account, %p)     = @_;
    $p{'Account'} = $Account;
    my $fnret = OVH::Bastion::check_args(\%p,
        mandatory => [qw{ Account }],
    );
    $fnret or return $fnret;

    $fnret = $this->isExisting();
    OVH::Bastion::osh_debug("Group($this)->hasAclkeeper($Account): this->isExisting==$fnret");
    $fnret or return $fnret;

    require OVH::Bastion::Account;
    $fnret = $Account->isExisting();
    OVH::Bastion::osh_debug("Group($this)->hasAclkeeper($Account): Account->isExisting==$fnret");
    $fnret or return $fnret;

    $fnret = OVH::Bastion::is_user_in_group(user => $Account->sysUser, group => $this->sysGroupAclkeeper);
    OVH::Bastion::osh_debug("Group($this)->hasAclkeeper($Account): $fnret");
    return $fnret if $fnret->is_err;
    return R('OK') if $fnret;
    return R('KO_NOT_GROUP_GATEKEEPER', msg => "Account '".$Account->name."' is not an aclkeeper of group '".$this->name."'");
}

sub hasMemberOrGuest {
    my ($this, $Account, %p)     = @_;
    $p{'Account'} = $Account;
    my $fnret = OVH::Bastion::check_args(\%p,
        mandatory => [qw{ Account }],
    );
    $fnret or return $fnret;

    $fnret = $this->isExisting();
    $fnret or return $fnret;

    require OVH::Bastion::Account;
    $fnret = $Account->isExisting();
    $fnret or return $fnret;

    $fnret = OVH::Bastion::is_user_in_group(user => $Account->sysUser, group => $this->sysGroup);
    return $fnret if $fnret->is_err;
    if ($fnret->is_ko) {
        return R('KO_NOT_GROUP_MEMBER_NOR_GUEST', msg => "Account '".$Account->name."' is not a member nor guest of group '".$this->name."'");
    }
    return R('OK');
}

_memoizify('hasMember');
sub hasMember {
    my ($this, $Account, %p)     = @_;
    $p{'Account'} = $Account;
    my $fnret = OVH::Bastion::check_args(\%p,
        mandatory => [qw{ Account }],
    );
    $fnret or return $fnret;

    $fnret = $this->hasMemberOrGuest($Account);
    $fnret or return $fnret;

    # do they have the allowed.ip symlink?
    my $prefix = $Account->remoteName ? "allowed_".$Account->remoteName : "allowed";
    if (-l "/home/allowkeeper/".$Account->sysUser."/$prefix.ip.".$this->name) { # FIXME shouldn't be there
        # -l => test that file exists and is a symlink
        # -r => test that the symlink dest still exists => REMOVED, because we (the caller) might not have the right
        #       to read the file if we're not member or guest ourselves
        return R('OK');
    }

    return R('KO_NOT_GROUP_MEMBER', msg => "Account '".$Account->name."' is not a member of group '".$this->name."'");
}

_memoizify('hasGuest');
sub hasGuest {
    my ($this, $Account, %p)     = @_;
    $p{'Account'} = $Account;
    my $fnret = OVH::Bastion::check_args(\%p,
        mandatory => [qw{ Account }],
    );
    $fnret or return $fnret;

    $fnret = $this->hasMemberOrGuest($Account);
    $fnret or return $fnret;

    # do they have the allowed.partial file?
    my $prefix = $Account->remoteName ? "allowed_".$Account->remoteName : "allowed";
    if (-f "/home/allowkeeper/".$Account->sysUser."/$prefix.partial.".$this->name) { # FIXME shouldn't be there
        return R('OK');
    }

    return R('KO_NOT_GROUP_GUEST', msg => "Account '".$Account->name."' is not a guest of group '".$this->name."'");
}

1;
