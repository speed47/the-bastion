package OVH::Bastion;

# vim: set filetype=perl ts=4 sw=4 sts=4 et:

use common::sense;

use Time::Piece;    # $t->strftime
use Carp;
use List::Util qw{ any none };

# Check if a system user belongs to a specific system group
sub is_user_in_group {
    my %p     = @_;
    my $fnret = OVH::Bastion::check_args(\%p, mandatory => [qw{ group user }]);
    $fnret or return $fnret;

    $fnret = OVH::Bastion::sys_getgr_name(name => $p{'group'});
    $fnret or return $fnret;

    if (grep { $p{'user'} eq $_ } @{$fnret->value->{'members'} || []}) {
        return R('OK', value => {group => $p{'group'}, account => $p{'user'}});
    }
    else {
        return R('KO_NOT_IN_GROUP', msg => "Account " . $p{'user'} . " doesn't belong to the group " . $p{'group'});
    }
}

# validate uid/gid
sub is_valid_uid {
    my %p     = @_;
    my $fnret = OVH::Bastion::check_args(\%p, mandatory => [qw{ uid type }]);
    $fnret or return $fnret;

    my ($uid, $type) = ($p{'uid'}, $p{'type'});

    # Basic input validation
    if ($uid !~ m/^\d+$/) {
        return R('ERR_INVALID_PARAMETER', msg => "Parameter 'uid' should be numeric");
    }

    if ($type ne 'user' and $type ne 'group') {
        return R('ERR_INVALID_PARAMETER', msg => "Parameter 'type' is invalid");
    }

    # Input validation against configuration
    $fnret = OVH::Bastion::load_configuration();
    $fnret or return $fnret;

    my ($accountUidMin, $accountUidMax, $ttyrecGroupIdOffset) =
      @{$fnret->value}{qw{ accountUidMin accountUidMax ttyrecGroupIdOffset }};

    if (not $accountUidMin or not $accountUidMax or not $ttyrecGroupIdOffset) {
        return R('ERR_CANNOT_LOAD_CONFIGURATION');
    }

    my ($low, $high) = ($accountUidMin, $accountUidMax);

    if ($type eq 'group') {
        $high += $ttyrecGroupIdOffset;
    }

    if ($uid < $low or $uid > $high) {
        return R('KO_BAD_RANGE', msg => "Parameter 'uid' should be between $low and $high");
    }

    # untaint
    if ($uid =~ m/^(\d+)$/) {
        return R('OK', value => $1);
    }
    warn_syslog("Got an invalid uid ('$uid')");
    return R('ERR_INVALID_UID', msg => "Got an invalid uid ('$uid')");
}

sub get_next_available_uid {
    my %p     = @_;
    my $fnret = OVH::Bastion::check_args(\%p, optionalFalseOk => [qw{ available_gid available_gid_ttyrec }]);
    $fnret or return $fnret;

    # if true, also check for the availability of the corresponding GID:
    my $available_gid = $p{'available_gid'};

    # if true, also check for the availability of the corresponding GID + the ttyrec offset:
    my $available_gid_ttyrec = $p{'available_gid_ttyrec'};

    my $higher = OVH::Bastion::config('accountUidMax')->value();
    my $lower  = OVH::Bastion::config('accountUidMin')->value();
    my $next   = $higher;
    my $found  = 0;
    while (1) {

        # find the first available UID, starting from the upper ID allowed and decrementing
        while ($next >= $lower) {
            last if not scalar(getpwuid($next));
            $next--;
        }

        # did we get out of the loop because we found a candidate, or because we're out of bounds?
        last if $next < $lower;

        # if $available_gid, also check if the corresponding GID is available
        # if $available_gid_ttyrec, also check if the corresponding GID + the ttyrec offset is available
        if (   (!$available_gid || !scalar(getgrgid($next)))
            && (!$available_gid_ttyrec || !scalar(getgrgid($next + OVH::Bastion::config('ttyrecGroupIdOffset')->value)))
          )
        {
            $found = 1;
            last;
        }

        # if we're here, at least one of the $available_gid* check failed, so continue looking
        $next--;
    }
    return R('OK',                value => $next) if $found;
    return R('ERR_UID_COLLISION', msg   => "No available UID in the allowed range");
}

# all ACL modifications (on groups, on accounts, including group-guests) are handled here
sub access_modify {
    my %p     = @_;
    my $fnret = OVH::Bastion::check_args(
        \%p,
        # action: add or del
        # ip: can be a single ip or prefix
        # way: group, groupguest, personal
        mandatory => [qw{ action ip way }],
        # user: if undef, means a user-wildcard access
        # port: if undef, means a port-wildcard access
        optionalFalseOk => [qw{ user port ttl comment forceKey forcePassword }],
        # Group: only for way=group or way=groupguest
        # Account: only for way=personal
        optional => [qw{ Account Group }],
    );
    $fnret or return $fnret;

    my $action = $p{'action'};    # add or del

    my $user = $p{'user'};        # if undef, means a user-wildcard access
    my $ip   = $p{'ip'};          # can be a single ip or prefix
    my $port = $p{'port'};        # if undef, means a port-wildcard access

    my $ttl     = $p{'ttl'};
    my $comment = $p{'comment'};

    my $way     = $p{'way'};        # group, groupguest, personal
    my $Group   = $p{'Group'};      # only for way=group or way=groupguest
    my $Account = $p{'Account'};    # only for way=personal

    my $forceKey      = $p{'forceKey'};
    my $forcePassword = $p{'forcePassword'};

    # due to how plugins work, sometimes user and port are just '', make them undef in those cases
    undef $user if (defined $user && $user eq '');
    undef $port if (defined $port && $port eq '');

    # check way
    if ($way eq 'personal') {
        return R('ERR_INVALID_PARAMETER', msg => "Group parameter specified with way=personal")   if $Group;
        return R('ERR_MISSING_PARAMETER', msg => "Account parameter mandatory with way=personal") if !$Account;
    }
    elsif ($way eq 'group') {
        return R('ERR_MISSING_PARAMETER', msg => "Group parameter mandatory with way=group")   if !$Group;
        return R('ERR_INVALID_PARAMETER', msg => "Account parameter specified with way=group") if $Account;
    }
    elsif ($way eq 'groupguest') {
        if (!$Account || !$Group) {
            return R('ERR_MISSING_PARAMETER', msg => "Account or group parameter missing with way=groupguest");
        }
    }
    else {
        return R('ERR_INVALID_PARAMETER', msg => "Parameter 'way' must be either personal, group or groupguest");
    }

    if ($action ne 'add' and $action ne 'del') {
        return R('ERR_INVALID_PARAMETER', msg => "Action should be either 'del' or 'add'");
    }

    # check ip
    $fnret = OVH::Bastion::is_valid_ip(ip => $ip, allowPrefixes => 1);
    return $fnret unless $fnret;
    $ip = $fnret->value->{'ip'};

    # check port
    if (defined $port) {
        $fnret = OVH::Bastion::is_valid_port(port => $port);
        return $fnret unless $fnret;
        $port = $fnret->value;
    }

    # check remote user
    if (defined $user) {
        $fnret = OVH::Bastion::is_valid_remote_user(user => $user);
        return $fnret unless $fnret;
        $user = $fnret->value;
    }

    # check account
    if ($Account) {
        $fnret = $Account->check();
        $fnret or return $fnret;

        # account must NOT be a realm_* account (but can be a realm/jdoe account)
        if (none { $Account->type eq $_ } qw{ local remote }) {
            return R('ERR_INVALID_ACCOUNT', msg => "The account '$Account' is neither a local or remote account");
        }
    }

    # check group
    if ($Group) {
        $fnret = $Group->check();
        $fnret or return $fnret;
    }

    # check key fingerprint
    if ($forceKey) {
        $fnret = OVH::Bastion::is_valid_fingerprint(fingerprint => $forceKey);
        $fnret or return $fnret;
        $forceKey = $fnret->value->{'fingerprint'};
    }

    # check password hash
    if ($forcePassword) {
        $fnret = OVH::Bastion::is_valid_hash(hash => $forcePassword);
        $fnret or return $fnret;
        $forcePassword = $fnret->value->{'hash'};
    }

    if ($ttl) {
        if ($ttl =~ /^(\d+)$/) {
            $ttl = $1;
        }
        else {
            return R('ERR_INVALID_PARAMETER', msg => "The TTL must be numeric");
        }
    }

    # check if the caller has the right to make the change they're asking
    # ... 1. either $> is allowkeeper and $ENV{'SUDO_USER'} is the requesting account
    # ... 2. or $> is $grouptomodify  and $ENV{'SUDO_USER'} is the requesting account

    my ($running_as) = (getpwuid($>))[0] =~ /([0-9a-zA-Z_.-]+)/;
    my ($requester)  = $ENV{'SUDO_USER'} =~ /([0-9a-zA-Z_.-]+)/;

    # requester can never be a realm_* account, because it's shared and should not be able to add access to anything
    my $RequesterAccount = OVH::Bastion::Account->newFromName($requester, check => 1);   # FIXME is this root sometimes?
    $fnret = $RequesterAccount->check();
    $fnret or return $fnret;

    if (none { $RequesterAccount->type eq $_ } qw{ local remote }) {
        warn_syslog("access_modify: requester account '$RequesterAccount' is not local or remote");
        return R('ERR_SECURITY_VIOLATION',
            msg => "The requester account '$RequesterAccount' is neither a local or remote account");
    }

    my @one_should_succeed;
    my $expected_running_as = 'allowkeeper';

    if ($way eq 'personal') {
        if ($RequesterAccount eq $Account) {
            push @one_should_succeed, $RequesterAccount->hasRole('self'.ucfirst($action).'PersonalAccess');
        }

        # this is not a else here: somebody who has the account* right doesn't need the self* right
        push @one_should_succeed, $RequesterAccount->hasRole('account'.ucfirst($action).'PersonalAccess');
    }
    elsif ($way eq 'group') {
        $expected_running_as = $Group->sysUser;
        push @one_should_succeed, $Group->hasAclkeeper($RequesterAccount, superowner => 1);
    }
    elsif ($way eq 'groupguest') {
        push @one_should_succeed, $Group->hasGatekeeper($RequesterAccount, superowner => 1);
    }

    if ($running_as ne $expected_running_as) {
        warn_syslog("Security violation: current running user ($running_as) unexpected (wanted $expected_running_as)");
        return R('ERR_SECURITY_VIOLATION', msg => "Current running user unexpected");
    }

    if (grep({ $_ } @one_should_succeed) == 0 && !$RequesterAccount->isLocalRoot) {
        warn_syslog("Security violation: requesting user '$RequesterAccount' doesn't have the right to do that "
              . "(way=$way, group="
              . ($Group ? '<u>' : $Group)
              . ")");
        return R('ERR_SECURITY_VIOLATION', msg => "You're not allowed to do that");
    }

    # now, check if the access we're being asked to change is already in place or not
    osh_debug("for action $action of $user\@$ip:$port of way $way with account=$Account and group=$Group "
          . "requested by $RequesterAccount, checking if already granted");
    $fnret = OVH::Bastion::is_access_way_granted(
        user    => $user,
        ip      => $ip,
        port    => $port,
        way     => $way,
        group   => ($Group ? $Group->name : undef),
        account => ($Account ? $Account->name : undef),
        exactMatch => 1,    # we're checking if the exact right we're asked to modify exists or not
    );
    osh_debug("... result is $fnret");

    if ($action eq 'add' and $fnret) {
        return R('OK_NO_CHANGE', msg => "The requested access to add was already granted");
    }
    elsif ($action eq 'del' and not $fnret) {
        return R('OK_NO_CHANGE', msg => "The requested access to delete was not found, no change made");
    }

    # ok, now do the change, first define this sub

    my $_access_modify_file = sub {
        my %sub_params = @_;
        my $file       = $sub_params{'file'};

        # we don't check our params or the rights because our caller already did, guaranteed by the scoping of this sub

        # check if we can access the file
        if (!(-e $file)) {

            # it doesn't exist yet, create it
            OVH::Bastion::touch_file($file, oct(644));
            if (!(-e $file)) {
                return R('ERR_CANNOT_CREATE_FILE', msg => "File '$file' is missing and couldn't be created");
            }
        }

        # can we write to it ?
        if (!(-w $file)) {
            return R('ERR_CANNOT_OPEN_FILE', msg => "File '$file' cannot be written to");
        }

        # build the line we're either adding or looking for (to delete it)
        my $entry = $ip;
        $entry = $user . "@" . $entry if defined $user;
        $entry = $entry . ":" . $port if defined $port;
        my $machine = $entry;

        my $t            = localtime(time);
        my $fmt          = "%Y-%m-%d %H:%M:%S";
        my $date         = $t->strftime($fmt);
        my $entryComment = "# $action by $requester on $date";

        # if we're adding it, append other parameters as comments
        if ($action eq 'add') {

            $entry .= " $entryComment";

            if ($forceKey) {

                # hash is case-sensitive only for new SHA256 format
                $forceKey = lc($forceKey) if ($forceKey !~ /^sha256:/i);
                $entry .= " # FORCEKEY=" . $forceKey;
            }
            if ($forcePassword) {
                $entry .= " # FORCEPASSWORD=" . $forcePassword;
            }
            if ($ttl) {
                $entry .= " # EXPIRY=" . (time() + $ttl);
            }
            if ($comment) {
                $comment =~ s{[#<>\\"']}{_}g;
                $entry .= " # COMMENT=<" . $comment . ">";
            }
        }

        # to be extra sure, remove any \n in $entry, which is impossible because we vetted all the params,
        # but if somehow we failed, we'll be sure it doesn't permit to add multiple rights at once
        $entry =~ s/[\r\n]*//gm;

        # now, do the change
        my $returnmsg;
        if ($action eq 'add') {
            osh_debug("going to add entry '$entry'");
            if (open(my $fh_file, '>>', $file)) {
                print $fh_file $entry . "\n";
                close($fh_file);
            }
            else {
                return R('ERR_CANNOT_OPEN_FILE', msg => "Error opening $file: $!");
            }
            my $ttlmsg =
              $ttl ? (' (expires in ' . OVH::Bastion::duration2human(seconds => $ttl)->value->{'human'} . ')') : '';
            $returnmsg = "Access to $machine successfully added$ttlmsg";
        }
        elsif ($action eq 'del') {
            if (open(my $fh_file, '<', $file)) {
                my $newFile;
                my $found = 0;
                while (my $line = <$fh_file>) {
                    if ($line =~ m{^\Q$entry\E(\s|$)}) {
                        chomp $line;
                        $line = "# $line # $comment\n";
                        $found++;
                    }
                    $newFile .= $line;
                }
                close($fh_file);

                if ($found) {

                    # now rewrite
                    if (open(my $fh_file, '>', $file)) {
                        print $fh_file $newFile;
                        close($fh_file);
                        $returnmsg = "Access to $machine successfully removed";
                    }
                    else {
                        return R('ERR_CANNOT_OPEN_FILE', msg => "Unable to write open $file");
                    }
                }
                else {
                    return R('OK_NO_CHANGE', msg => "Entry $entry was not present in file $file");
                }
            }
        }
        OVH::Bastion::syslog_formatted(
            severity => 'info',
            type     => 'acl',
            fields   => [
                ['action',         $p{'action'}],
                ['type',           $p{'way'}],
                ['group',          $p{'Group'}?$p{'Group'}->name:''],
                ['account',        $p{'Account'}?$p{'Account'}->name:''],
                ['user',           $p{'user'}],
                ['ip',             $p{'ip'}],
                ['port',           $p{'port'}],
                ['ttl',            $p{'ttl'}],
                ['force_key',      $p{'forceKey'}],
                ['force_password', $p{'forcePassword'}],
                ['comment',        $p{'comment'}],
            ]
        );
        return R('OK', msg => $returnmsg) if $returnmsg;
        return R('ERR_INTERNAL');
    };    # end of sub definition

    # then call the sub we just defined
    delete $p{'file'};
    my $ret;
    if ($way eq 'personal') {
        $ret = $_access_modify_file->(%p, file => $Account->allowedPrivateFile);
    }
    elsif ($way eq 'group') {
        $ret = $_access_modify_file->(%p, file => $Group->allowedIpFile);
    }
    elsif ($way eq 'groupguest') {
        $ret = $_access_modify_file->(%p, file => $Account->allowedGuestFile($Group));
    }
    osh_debug("_access_modify_file() said $ret");
    return $ret if defined $ret;

    return R('ERR_INTERNAL');    # unreachable
}

# return the list of the bastion groups (i.e. not the system group list)
sub get_group_list {
    my %p     = @_;
    my $fnret = OVH::Bastion::check_args(
        \%p,
        optionalFalseOk => [qw{ fast }],
    );
    $fnret or return $fnret;

    $fnret = OVH::Bastion::sys_getgr_all();
    $fnret or return $fnret;

    my %groups;
    foreach my $name (keys %{$fnret->value}) {
        my $Group = OVH::Bastion::Group->newFromSysGroup($name);
        next if !$Group;

        if ($p{'fast'}) {
            $groups{$Group->name} = $Group;
        }
        else {
            $groups{$Group->name} = $Group if $Group->isExisting();
        }
    }
    return R('OK', value => \%groups);
}

# return the list of bastion accounts (i.e. not the system user list)
sub get_account_list {
    my %p     = @_;
    my $fnret = OVH::Bastion::check_args(
        \%p,
        optional        => [qw{ accounts }],
        optionalFalseOk => [qw{ fast }],
    );
    $fnret or return $fnret;

    my $accounts = $p{'accounts'} || [];
    my $fast     = $p{'fast'};             # don't call ->isExisting() on each account (uid/gid will NOT be set)

    # we loop through all the accounts known to the OS
    $fnret = OVH::Bastion::sys_getpw_all();
    $fnret or return $fnret;

    my %users;
    foreach my $name (keys %{$fnret->value}) {
        # if $accounts has been specified, only consider those
        next if (@$accounts && none { $name eq $_ } @$accounts);

        my $Account = OVH::Bastion::Account->newFromName($name);
        next if !$Account;

        if ($fast) {
            $users{$name} = $Account;
        }
        else {
            $users{$name} = $Account if $Account->isExisting();
        }
    }

    return R('OK', value => \%users);
}

sub get_realm_list {
    my %p     = @_;
    my $fnret = OVH::Bastion::check_args(\%p, optional => [qw{ realms }],);
    $fnret or return $fnret;

    my $realms = $p{'realms'} || [];

    # we loop through all the accounts known to the OS
    $fnret = OVH::Bastion::sys_getpw_all();
    $fnret or return $fnret;

    my %users;
    foreach my $name (keys %{$fnret->value}) {
        # if $realms has been specified, only consider those
        next if (@$realms && none { $name eq "realm_$_" } @$realms);

        # skip invalid realms.
        my $RealmSupportAccount = OVH::Bastion::Account->newFromName($name, type => "realm", check => 1);
        next if !$RealmSupportAccount;

        # add proper realms
        $name = $RealmSupportAccount->realm;
        $users{$name} = {name => $name};
    }

    return R('OK', value => \%users);
}

sub is_valid_ttl {
    my %p     = @_;
    my $fnret = OVH::Bastion::check_args(\%p, mandatoryFalseOk => [qw{ ttl }],);
    $fnret or return $fnret;

    my $ttl = $p{'ttl'};
    my $seconds;

    if ($ttl =~ /^\d+$/) {
        return R('OK', value => {seconds => $ttl + 0});
    }
    elsif ($ttl =~ m{^(\d+[smhdwy]*)+$}i) {
        while ($ttl =~ m{(\d+)([smhdwy])?}gi) {
            if    ($2 eq 'y') { $seconds += $1 * 86400 * 365 }
            elsif ($2 eq 'w') { $seconds += $1 * 86400 * 7 }
            elsif ($2 eq 'd') { $seconds += $1 * 86400 }
            elsif ($2 eq 'h') { $seconds += $1 * 3600 }
            elsif ($2 eq 'm') { $seconds += $1 * 60 }
            else              { $seconds += $1 }
        }
        return R('OK', value => {seconds => $seconds + 0});
    }

    return R('KO_INVALID_PARAMETER',
        msg => "Invalid TTL ($ttl), expected an amount of seconds, or a duration string such as '2d8h15m'");
}

# used by groupList and accountList
sub build_re_from_wildcards {
    my %p     = @_;
    my $fnret = OVH::Bastion::check_args(
        \%p,
        mandatory       => [qw{ wildcards }],
        optionalFalseOk => [qw{ implicit_contains }],
    );
    $fnret or return $fnret;

    my $wildcards         = $p{'wildcards'};
    my $implicit_contains = $p{'implicit_contains'};

    # to avoid modifying the caller's array
    my @relist = @$wildcards;

    # qr// is true, so return undef if there's nothing to build
    return R('OK', value => undef) if !@relist;

    for (@relist) {
        if ($implicit_contains) {

            # if we have a word without any ? or *, guess that the user expects a "contains" behavior, i.e. *item*
            $_ = '*' . $_ . '*' if not /[\*\?]/;
        }
        $_ = quotemeta;
        s/\\\*/.*/g;
        s/\\\?/./g;
        $_ = '^' . $_ . '$';
    }
    my $stringified = join("|", @relist);
    return R('OK', value => qr/$stringified/);
}

1;
