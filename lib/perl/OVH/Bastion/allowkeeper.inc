package OVH::Bastion;

# vim: set filetype=perl ts=4 sw=4 sts=4 et:

use common::sense;

use Time::Piece;    # $t->strftime
use Carp;
use List::Util qw{ any none };

sub is_bastion_account_valid_and_existing {    # FIXME kill me after MIGRA
    my %params = @_;
    my $A      = OVH::Bastion::Account->newFromName($params{'account'}, check => 1);
    $A or return $A;
    return R(
        'OK',
        value => {
            account       => $A->name,
            sysaccount    => $A->sysUser,
            remoteaccount => $A->remoteName,
            realm         => $A->realm,
            home          => $A->home
        }
    );
}

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

# does this system group exist? if it happens to be mapped to a bastion group,
# also return the corresponding "shortGroup" (with the "key" prefix removed)
sub is_group_existing {
    my %p     = @_;
    my $fnret = OVH::Bastion::check_args(
        \%p,
        mandatory => [qw{ group }],
        optional  => [qw{ groupType user_friendly_error }],
    );
    $fnret or return $fnret;

    my $group = $p{'group'};

    $fnret = OVH::Bastion::sys_getgr_name(name => $group);

    if ($fnret) {
        my (undef, $shortGroup) = $group =~ m{^(key)?(.+)};
        return R(
            'OK',
            value => {
                group      => $group,
                shortGroup => $shortGroup,
                gid        => $fnret->value->{'gid'},
                keyhome    => "/home/keykeeper/$group",
                members    => $fnret->value->{'members'},
            }
        );
    }

    # build a user-compatible error message if asked to, as it can make its way through osh_exit()
    if ($p{'user_friendly_error'}) {    # FIXME remove this ugly thing
        $group =~ s/^key//;
        return R('KO_GROUP_NOT_FOUND',
            msg => "The bastion group '$group' doesn't exist.\n"
              . "You may use groupList --all to see all existing groups.");
    }
    return R('KO_GROUP_NOT_FOUND', msg => "Group '$group' doesn't exist");
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
        # group: only for way=group or way=groupguest
        # Account: only for way=personal
        optional => [qw{ Account group }],
    );
    $fnret or return $fnret;

    my $action = $p{'action'};    # add or del

    my $user = $p{'user'};        # if undef, means a user-wildcard access
    my $ip   = $p{'ip'};          # can be a single ip or prefix
    my $port = $p{'port'};        # if undef, means a port-wildcard access

    my $ttl     = $p{'ttl'};
    my $comment = $p{'comment'};

    my $way     = $p{'way'};        # group, groupguest, personal
    my $group   = $p{'group'};      # only for way=group or way=groupguest
    my $Account = $p{'Account'};    # only for way=personal

    my $forceKey      = $p{'forceKey'};
    my $forcePassword = $p{'forcePassword'};

    # due to how plugins work, sometimes user and port are just '', make them undef in those cases
    undef $user if (defined $user && $user eq '');
    undef $port if (defined $port && $port eq '');

    # check way
    if ($way eq 'personal') {
        return R('ERR_INVALID_PARAMETER', msg => "Group parameter specified with way=personal")   if defined $group;
        return R('ERR_MISSING_PARAMETER', msg => "Account parameter mandatory with way=personal") if !$Account;
    }
    elsif ($way eq 'group') {
        return R('ERR_MISSING_PARAMETER', msg => "Group parameter mandatory with way=group")   if !defined $group;
        return R('ERR_INVALID_PARAMETER', msg => "Account parameter specified with way=group") if $Account;
    }
    elsif ($way eq 'groupguest') {
        if (!$Account || !defined $group) {
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
        # accountType==normal : account must NOT be a realm_* account (but can be a realm/jdoe account)
        $fnret = $Account->check();
        $fnret or return $fnret;

        if (none { $Account->type eq $_ } qw{ local remote }) {
            return R('ERR_INVALID_ACCOUNT', msg => "The account '$Account' is neither a local or remote account");
        }
    }

    # check group
    my $shortGroup;
    if (defined $group) {
        $fnret = OVH::Bastion::is_valid_group_and_existing(group => $group, groupType => 'key');
        $fnret or return $fnret;
        $group      = $fnret->value->{'group'};         # untainted
        $shortGroup = $fnret->value->{'shortGroup'};    # untainted
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
            push @one_should_succeed,
              OVH::Bastion::is_user_in_group(
                user  => $RequesterAccount->sysUser,
                group => 'osh-self' . ucfirst($action) . 'PersonalAccess',
              );
        }

        # this is not a else here: somebody who has the account* right doesn't need the self* right
        push @one_should_succeed,
          OVH::Bastion::is_user_in_group(
            user  => $RequesterAccount->sysUser,
            group => 'osh-account' . ucfirst($action) . 'PersonalAccess',
          );
    }
    elsif ($way eq 'group') {
        $expected_running_as = $group;
        push @one_should_succeed,
          OVH::Bastion::is_group_aclkeeper(
            account    => $RequesterAccount->sysUser,
            group      => $shortGroup,
            superowner => 1
          );
    }
    elsif ($way eq 'groupguest') {
        push @one_should_succeed,
          OVH::Bastion::is_group_gatekeeper(
            account    => $RequesterAccount->sysUser,
            group      => $shortGroup,
            superowner => 1
          );
    }

    if ($running_as ne $expected_running_as) {
        warn_syslog("Security violation: current running user ($running_as) unexpected (wanted $expected_running_as)");
        return R('ERR_SECURITY_VIOLATION', msg => "Current running user unexpected");
    }

    if (grep({ $_ } @one_should_succeed) == 0 && !$RequesterAccount->isLocalRoot) {
        warn_syslog("Security violation: requesting user '$RequesterAccount' doesn't have the right to do that "
              . "(way=$way, group="
              . ($shortGroup ? '<u>' : $shortGroup)
              . ")");
        return R('ERR_SECURITY_VIOLATION', msg => "You're not allowed to do that");
    }

    # now, check if the access we're being asked to change is already in place or not
    osh_debug("for action $action of $user\@$ip:$port of way $way with account=$Account and group=$group "
          . "requested by $RequesterAccount, checking if already granted");
    $fnret = OVH::Bastion::is_access_way_granted(
        user    => $user,
        ip      => $ip,
        port    => $port,
        way     => $way,
        group   => $shortGroup,
        account => $Account ? $Account->name : undef,
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
        OVH::Bastion::syslogFormatted(
            severity => 'info',
            type     => 'acl',
            fields   => [
                ['action',         $p{'action'}],
                ['type',           $p{'way'}],
                ['group',          $shortGroup],
                ['account',        $p{'account'}],
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
    my $prefix = ($Account && $Account->remoteName) ? "allowed_" . $Account->remoteName : "allowed";
    if ($way eq 'personal') {
        $ret = $_access_modify_file->(%p, file => $Account->allowedPrivateFile);
    }
    elsif ($way eq 'group') {
        $ret = $_access_modify_file->(%p, file => "/home/$group/allowed.ip");
    }
    elsif ($way eq 'groupguest') {
        $ret =
          $_access_modify_file->(%p, file => "/home/allowkeeper/" . $Account->sysUser . "/$prefix.partial.$shortGroup");
    }
    osh_debug("_access_modify_file() said $ret");
    return $ret if defined $ret;

    return R('ERR_INTERNAL');    # unreachable
}

# Check that a group is valid or not (syntax)
sub is_valid_group {
    my %p     = @_;
    my $fnret = OVH::Bastion::check_args(
        \%p,
        mandatory => [qw{ group }],
        optional  => [qw{ groupType }],
    );
    $fnret or return $fnret;

    my $group     = $p{'group'};
    my $groupType = $p{'groupType'};

    # possible groupTypes:
    # osh: osh-accountList
    # tty: login8-tty
    # key: keymygroup
    # gatekeeper: keymygroup-gatekeeper
    # aclkeeper: keymygroup-aclkeeper
    # owner: keymygroup-owner
    # regular: no check appart from the length and forbidden prefixes/suffixes

    # autodetect if my caller prefixed the group name with 'key' or not, and adjust accordingly.
    # we'll return normalized group and shortGroup values to our caller
    if ($group !~ /^key/ && defined $groupType && grep { $groupType eq $_ } qw{ key gatekeeper aclkeeper owner }) {
        $group = "key$group";
    }

    if ($group =~ m/keeper$/i and not grep { $groupType eq $_ } qw{ gatekeeper aclkeeper }) {
        return R('KO_FORBIDDEN_SUFFIX', msg => 'Forbidden suffix in group name');
    }
    elsif ($group =~ m/owner$/i and $groupType ne 'owner') {
        return R('KO_FORBIDDEN_SUFFIX', msg => 'Forbidden suffix in group name');
    }
    elsif ($group =~ m/-tty$/i and $groupType ne 'tty') {
        return R('KO_FORBIDDEN_SUFFIX', msg => 'Forbidden suffix in group name');
    }
    elsif ($group =~ m/^key/i and not grep { $groupType eq $_ } qw{ key gatekeeper owner }) {
        return R('KO_FORBIDDEN_PREFIX', msg => 'Forbidden prefix in group name');
    }
    elsif ($group =~ m/^[-.]/) {
        return R('KO_FORBIDDEN_PREFIX', msg => "Group name can't start with a '-' nor a '.'");
    }
    elsif ($group =~ /^(key)?(private|root|user|self|legacy|osh)(-(gatekeeper|aclkeeper|owner))?$/) {
        return R('KO_FORBIDDEN_NAME', msg => 'Forbidden group name');
    }
    elsif ($group =~ m/^([a-zA-Z0-9._-]+)$/) {
        $group = $1;    # untainted
        if ($groupType eq 'key' and $group !~ m/^key/) {
            return R('KO_MISSING_PREFIX', msg => "The group $group should have a prefix (group type $groupType)");
        }
        elsif ($groupType eq 'gatekeeper' and $group !~ m/^key.+-gatekeeper$/) {
            return R('KO_MISSING_PREFIX', msg => "The group $group should have a prefix (group type $groupType)");
        }
        elsif ($groupType eq 'owner' and $group !~ m/^key.+-owner$/) {
            return R('KO_MISSING_PREFIX', msg => "The group $group should have a prefix (group type $groupType)");
        }
        elsif ($groupType and $groupType eq 'tty' and $group !~ m/-tty$/) {
            return R('KO_MISSING_SUFFIX', msg => "The group $group should have a suffix (group type $groupType)");
        }
        my $shortGroup = $group;
        $shortGroup =~ s/^key|^osh-|-(gatekeeper|aclkeeper|owner|tty)$//g;

        if (length($group) > 32) {

            # 32 max for the whole group (system limit)
            return R('KO_NAME_TOO_LONG', msg => 'Group name is too long (system limit)');
        }

        # 18 max for the short group name, because 32 - length(key) - length(-gatekeeper) == 18
        if ((grep { $groupType eq $_ } qw{ key gatekeeper aclkeeper owner }) && (length($shortGroup) > 18)) {
            return R('KO_NAME_TOO_LONG', msg => "Group name is too long (limit is 18 chars)");
        }

        return R('OK', value => {group => $group, shortGroup => $shortGroup});
    }
    return R('KO_FORBIDDEN_NAME', msg => 'Group name contains invalid characters');
}

sub is_valid_group_and_existing {
    my %params = @_;

    my $fnret = OVH::Bastion::is_valid_group(%params);
    $fnret or return $fnret;
    $params{'group'} = $fnret->value->{'group'};
    return OVH::Bastion::is_group_existing(%params, user_friendly_error => 1);
}

# return the list of the bastion groups (i.e. not the system group list)
sub get_group_list {
    my %p     = @_;
    my $fnret = OVH::Bastion::check_args(\%p);
    $fnret or return $fnret;

    # we loop through all the system groups and only retain those starting
    # with "key", and not finishing in -owner, -gatekeeper or -aclkeeper.
    # we also exclude special builtin groups (keykeeper and keyreader)
    $fnret = OVH::Bastion::sys_getgr_all();
    $fnret or return $fnret;

    my %groups;
    foreach my $name (keys %{$fnret->value}) {
        if (   $name =~ /^key/
            && $name !~ /-(?:owner|gatekeeper|aclkeeper)$/
            && !grep { $name eq $_ } qw{ keykeeper keyreader })
        {
            my $entry = $fnret->value->{$name};
            $name =~ s/^key//;
            $groups{$name} = {gid => $entry->{'gid'}, members => $entry->{'members'}} if ($name ne '');
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

# used by funcs below
sub _has_group_role {
    my %p     = @_;
    my $fnret = OVH::Bastion::check_args(
        \%p,
        mandatory       => [qw{ account group role }],
        optionalFalseOk => [qw{ superowner }],
    );
    $fnret or return $fnret;

    my $account    = $p{'account'};
    my $shortGroup = $p{'group'};
    my $role       = $p{'role'};          # regular or gatekeeper or owner
    my $superowner = $p{'superowner'};    # allow superowner (will always return yes if so)

    my $group = "key$shortGroup";

    # "regular" means "member or guest", i.e. user is in group key$GROUPNAME
    if ($role ne 'regular') {
        $group .= "-$role";
    }

    # for the realm case, we need to test sysaccount and not just account
    my $Account = OVH::Bastion::Account->newFromName($account);
    $Account or return $Account;

    $fnret = $Account->isExisting();
    $fnret or return $fnret;

    my $sysaccount = $Account->sysUser;

    $fnret = OVH::Bastion::is_user_in_group(user => $sysaccount, group => $group);
    osh_debug("is <$sysaccount> in <$group> ? => " . ($fnret ? 'yes' : 'no'));
    if ($fnret) {
        return R(
            $fnret->err,
            msg   => $fnret->msg,
            value => {account => $account, sysaccount => $sysaccount, superowner => 0}
        );
    }

    # if superowner allowed, try it
    if ($superowner) {
        if ($Account->isSuperOwner) {
            osh_debug("is <$sysaccount> in <$group> ? => no but superowner so YES!");
            return R('OK', value => {account => $account, sysaccount => $sysaccount, superowner => 1});
        }
    }

    # not admin or no superowner allowed... return is_user_in_group status but fixup the value if true
    if ($fnret) {
        return R(
            $fnret->err,
            msg   => $fnret->msg,
            value => {account => $account, sysaccount => $sysaccount, superowner => 0}
        );
    }
    return $fnret;
}

sub is_group_aclkeeper {
    my %params = @_;
    $params{'role'} = 'aclkeeper';
    return _has_group_role(%params);
}

sub is_group_gatekeeper {
    my %params = @_;
    $params{'role'} = 'gatekeeper';
    return _has_group_role(%params);
}

sub is_group_owner {
    my %params = @_;
    $params{'role'} = 'owner';
    return _has_group_role(%params);
}

sub _is_group_member_or_guest {
    my %p     = @_;
    my $fnret = OVH::Bastion::check_args(\%p, mandatory => [qw{ group account want }],);

    my $shortGroup = $p{'group'};
    my $want       = $p{'want'};    # guest or member

    $fnret = _has_group_role(group => $p{'group'}, account => $p{'account'}, role => "regular");
    $fnret or return $fnret;

    my $account = $fnret->value()->{'account'};
    $fnret = OVH::Bastion::is_bastion_account_valid_and_existing(account => $account);
    $fnret or return $fnret;

    $account = $fnret->value->{'account'};
    my $remoteaccount = $fnret->value->{'remoteaccount'};
    my $sysaccount    = $fnret->value->{'sysaccount'};

    my $group = "key$shortGroup";
    $fnret = OVH::Bastion::is_valid_group_and_existing(group => $group, groupType => "key");
    $fnret or return $fnret;
    $group      = $fnret->value()->{'group'};
    $shortGroup = $fnret->value()->{'shortGroup'};    # untainted

    my $weare = 'guest';

    # to be a member (old name: "full member"); one also need to have the symlink
    my $prefix = $remoteaccount ? "allowed_$remoteaccount" : "allowed";
    if (-l "/home/allowkeeper/$sysaccount/$prefix.ip.$shortGroup") {

        # -l => test that file exists and is a symlink
        # -r => test that the symlink dest still exists => REMOVED, because we (the caller) might not have the right to read the file if we're not member or guest ourselves
        $weare = 'member';
    }

    return R('OK') if ($weare eq $want);
    return R('KO');
}

# test if account is strictly a guest (i.e. if a member, then answer is no)
sub is_group_guest {
    my %p = @_;
    return _is_group_member_or_guest(want => 'guest', group => $p{'group'}, account => $p{'account'});
}

# test if account is strictly a member (i.e. if a guest, then answer is no)
sub is_group_member {
    my %p = @_;
    return _is_group_member_or_guest(want => 'member', group => $p{'group'}, account => $p{'account'});
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
