package OVH::Bastion::Plugin::groupSetRole;

# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use common::sense;

use File::Basename;
use lib dirname(__FILE__) . '/../../../../../lib/perl';
use OVH::Result;
use OVH::Bastion;

sub preconditions {
    my %p     = @_;
    my $fnret = OVH::Bastion::check_args(\%p,
        mandatory       => [qw{ Self role action }],
        optional        => [qw{ host scriptName savedArgs account Account group Group }],
        optionalFalseOk => [qw{ user userAny port portAny ttl isHelper silentoverride comment }],
    );
    $fnret or return $fnret;

    if (!$p{'account'} && !$p{'Account'}) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing the 'account' parameter");
    }
    if (!$p{'group'} && !$p{'Group'}) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing the 'group' parameter");
    }

    if (!grep { $p{'action'} eq $_ } qw{ add del }) {
        return R('ERR_INVALID_PARAMETER', msg => "Action should be add or del");
    }

    # a regex is overkill here but we need it for untaint
    if ($p{'role'} =~ /^(owner|gatekeeper|aclkeeper|member|guest)$/) {    ## no critic (ProhibitFixedStringMatches)
        $p{'role'} = $1;
    }
    else {
        return R('ERR_INVALID_PARAMETER', msg => "Type should be either owner, gatekeeper, aclkeeper, member or guest");
    }

    my $Account = $p{'Account'} || OVH::Bastion::Account->newFromName($p{'account'});
    $Account or return $Account;
    $fnret = $Account->check();
    $fnret or return $fnret;

    my $Group = $p{'Group'} || OVH::Bastion::Group->newFromName($p{'group'});
    $Group or return $Group;
    $fnret = $Group->check();
    $fnret or return $fnret;

    if ($p{'role'} eq 'guest' && !$p{'isHelper'}) {

        # guest access need (user||user-any), host and (port||port-any)
        # in helper mode, these are not used, because the helper doesn't handle the guest access add by itself, the act() func of this package does
        if (!($p{'user'} xor $p{'userAny'})) {
            return R('ERR_MISSING_PARAMETER', msg => "Require exactly one argument of user or user-any");
        }
        if (!($p{'port'} xor $p{'portAny'})) {
            return R('ERR_MISSING_PARAMETER', msg => "Require exactly one argument of port or port-any");
        }
        if (not $p{'host'}) {
            return R('ERR_MISSING_PARAMETER', msg => "Missing argument host for role guest");
        }
        if ($p{'port'}) {
            $fnret = OVH::Bastion::is_valid_port(port => $p{'port'});
            $fnret or return $fnret;
        }
        if ($p{'user'} and $p{'user'} !~ /^[a-zA-Z0-9!._-]+$/) {
            return R('ERR_INVALID_PARAMETER', msg => "Invalid remote user ($p{'user'}) specified");
        }

        if ($p{'action'} eq 'add') {

            # policy check for guest accesses: if group forces ttl, the account creation must comply
            $fnret = $Group->getConfig("guest_ttl_limit");

            # if this config key is not set, no policy enforce has been requested, otherwise, check it:
            if ($fnret) {
                my $max = $fnret->value();
                if (!$p{'ttl'}) {
                    return R('ERR_INVALID_PARAMETER',
                            msg => "This group requires guest accesses to have a TTL set, to a duration of "
                          . OVH::Bastion::duration2human(seconds => $max)->value->{'duration'}
                          . " or less");
                }
                if ($p{'ttl'} > $max) {
                    return R('ERR_INVALID_PARAMETER',
                        msg => "The TTL you specified is invalid, this group requires guest accesses to have a TTL of "
                          . OVH::Bastion::duration2human(seconds => $max)->value->{'duration'}
                          . " maximum");
                }
            }
        }
    }

    my $Self = $p{'Self'};
    if ($Self->isa("OVH::Result") && $Self->code eq 'KO_FORBIDDEN_NAME' && $p{'calledByRoot'} && $< == 0) {
        ;    # special case where we're called by the groupSetRole helper, it's ok
             # FIXME still needed?
    }
    else {
        $fnret = $Self->selfCheck();
        $fnret or return $fnret;
    }

    if ($p{'calledByRoot'}) {    # FIXME still needed? not set anywhere
        osh_debug("called by root, allowing anyway");
    }
    else {
        my $neededright = 'unknown';
        if (grep { $p{'role'} eq $_ } qw{ owner gatekeeper aclkeeper }) {
            $neededright = "owner";
            $fnret       = $Group->hasOwner($Self, superowner => 1);
            if (!$fnret) {
                osh_debug("user $Self not an owner of $Group");
                return R('ERR_NOT_GROUP_OWNER',
                        msg => "Sorry, you're not an owner of group $Group, which is needed to change its "
                      . $p{'role'}
                      . " list");
            }

            # if account is from a realm, they can't be owner/gk/aclk
            if ($Account->realm) {
                return R('ERR_REALM_USER',
                    msg => "Sorry, " . $Account->name . " is from another realm, this account can't be " . $p{'role'});
            }
        }
        elsif (grep { $p{'role'} eq $_ } qw{ member guest }) {
            $neededright = "gatekeeper";
            $fnret       = $Group->hasGatekeeper($Self, superowner => 1);
            if (!$fnret) {
                osh_debug("user $Self is not a gatekeeper of $Group");
                return R('ERR_NOT_GROUP_GATEKEEPER',
                        msg => "Sorry, you're not a gatekeeper of group $Group, which is needed to change its "
                      . $p{'role'}
                      . " list");
            }
        }
        else {
            return R('ERR_INTERNAL', msg => "Unknown role " . $p{'role'});
        }

        if ($fnret->value() && $fnret->value()->{'superowner'} && !$p{'silentoverride'}) {
            osh_warn "SUPER OWNER OVERRIDE: You're not a $neededright of the group $Group,";
            osh_warn "but allowing because you're a superowner. This has been logged.";

            OVH::Bastion::syslog_formatted(
                criticity => 'info',
                type      => 'security',
                fields    => [
                    ['type',    'superowner-override'],
                    ['account', $Self->name],
                    ['plugin',  $p{'scriptName'}],
                    ['params',  $p{'savedArgs'}],
                ]
            );
        }
    }

    return R(
        'OK',
        value => {
            Group      => $Group,
            Account    => $Account,
            role       => $p{'role'},
        }
    );
}

sub act {
    my %p = @_;
    use Data::Dumper;
    print Dumper(\%p);
    my $fnret = preconditions(%p);    # check_args is done there
    $fnret or return $fnret;

    # get returned untainted value
    my %values = %{$fnret->value()};
    my ($Group, $Account, $role) = @values{qw{ Group Account role }};
    my ($action, $user, $host, $port, $ttl, $comment) = @p{qw{ action user host port ttl comment }};

    my $Self = $p{'Self'};

    undef $user if $p{'userAny'};
    undef $port if $p{'portAny'};
    my @command;

    osh_debug("groupSetRole::act, $action $role $Group/$Account $user\@$host:$port ttl=$ttl comment=$comment");

    # add/del system user to system group except if we're removing a guest access (will be done after if needed)
    if (!($role eq 'guest' and $action eq 'del')) {
        @command = ();
        if ($< != 0) {
            # don't use sudo if we're already running under root through sudo, this way we keep the SUDO_USER intact
            # and in the helper below, we build the proper $Self. This happens when a helper calls us.
            push @command, qw{ sudo -n -u root -- };
        }
        push @command, qw{ /usr/bin/env perl -T };
        push @command, $OVH::Bastion::BASEPATH . '/bin/helper/osh-groupSetRole';
        push @command, '--type', $role;
        push @command, '--group', $Group->sysGroup;
        push @command, '--account', $Account->name;
        push @command, '--action', $action;
        $fnret = OVH::Bastion::helper(cmd => \@command);
        $fnret or return $fnret;
    }

    if ($role eq 'member') {

        if ($action eq 'add' && $Group->hasGuest($Account)) {
            # if the user is a guest, must remove all their guest accesses first
            $fnret = OVH::Bastion::get_acl_way(way => 'groupguest', group => $Group->name, account => $Account->name);
            if ($fnret && $fnret->value && @{$fnret->value}) {
                osh_warn("This account was previously a guest of this group, with the following accesses:");
                my @acl = @{$fnret->value};
                OVH::Bastion::print_acls(acls => [{type => 'group-guest', group => $Group->name, acl => \@acl}]);

                osh_info("\nCleaning these guest accesses before granting membership...");

                # foreach guest access, delete
                foreach my $access (@acl) {
                    my $machine = $access->{'ip'};
                    $machine .= ':' . $access->{'port'} if defined $access->{'port'};
                    $machine = $access->{'user'} . '@' . $machine if defined $access->{'user'};
                    $fnret   = OVH::Bastion::Plugin::groupSetRole::act(
                        Self    => $Self,
                        Account => $Account,
                        Group   => $Group,
                        action  => 'del',
                        role    => 'guest',
                        user    => $access->{'user'},
                        userAny => (defined $access->{'user'} ? 0 : 1),
                        port    => $access->{'port'},
                        portAny => (defined $access->{'port'} ? 0 : 1),
                        host    => $access->{'ip'},
                    );
                    if (!$fnret) {
                        osh_warn("Failed removing guest access to $machine, proceeding anyway...");
                        warn_syslog("Failed removing guest access to $machine in group $Group for $Account, "
                              . "before granting this account full membership on behalf of $Self: "
                              . $fnret->msg);
                    }
                }
            }
        }

        # then, for add and del, we need to handle the symlink
        @command = qw{ sudo -n -u allowkeeper -- /usr/bin/env perl -T };
        push @command, $OVH::Bastion::BASEPATH . '/bin/helper/osh-groupAddSymlinkToAccount';
        push @command, '--group', $Group->sysGroup;    # must be first param, forced in sudoers.d
        push @command, '--account', $Account->name;
        push @command, '--action',  $action;
        $fnret = OVH::Bastion::helper(cmd => \@command);
        $fnret or return $fnret;

        if ($fnret->err eq 'OK_NO_CHANGE') {

            # make the error msg user friendly
            $fnret->{'msg'} =
                "Account $Account was already "
              . ($action eq 'del' ? 'not ' : '')
              . "a member of $Group, nothing to do";
        }
    }
    elsif ($role eq 'guest') {

        # in that case, we need to handle the add/del of the guest access to $user@$host:$port
        # check if group has access to $user@$ip:$port
        my $machine = $host;
        $port and $machine .= ":$port";
        $user and $machine = $user . '@' . $machine;
        osh_debug(
            "groupSetRole::act, checking if group $Group has access to $machine to $action $role access to $Account");

        if ($action eq 'add') {

            $fnret = OVH::Bastion::is_access_way_granted(
                way   => 'group',
                group => $Group->name,
                user  => $user,
                port  => $port,
                ip    => $host,
            );
            if (not $fnret) {
                osh_debug("groupSetRole::act, it doesn't! $fnret");
                return R('ERR_GROUP_HAS_NO_ACCESS',
                    msg =>
                      "The group $Group doesn't have access to $machine, so you can't add a guest group access "
                      . "to it (first add it to the group if applicable, with groupAddServer)");
            }

            # if no comment was specified for this guest access, reuse the one from the matching group ACL entry
            $comment ||= $fnret->value->{'comment'};
        }

        # If the account is already a member, can't add/del them as guest
        if ($Group->hasMember($Account)) {
            return R('ERR_MEMBER_CANNOT_BE_GUEST',
                msg => "Can't $action $Account as a guest of group $Group, they're already a member!");
        }

        # Add/Del user access to user@host:port with group key
        @command = qw{ sudo -n -u allowkeeper -- /usr/bin/env perl -T };
        push @command, $OVH::Bastion::BASEPATH . '/bin/helper/osh-accountAddGroupServer';
        push @command, '--group', $Group->sysGroup;    # must be first param, forced in sudoers.d
        push @command, '--account', $Account->name;
        push @command, '--action',  $action;
        push @command, '--ip',      $host;
        push @command, '--user',    $user if $user;
        push @command, '--port',    $port if $port;
        push @command, '--ttl',     $ttl if $ttl;
        push @command, '--comment', $comment if $comment;

        $fnret = OVH::Bastion::helper(cmd => \@command);
        $fnret or return $fnret;

        if ($fnret->err eq 'OK_NO_CHANGE') {
            if ($action eq 'add') {
                osh_info "Account $Account already had access to $machine through $Group";
            }
            else {
                osh_info "Account $Account didn't have access to $machine through $Group";
            }
        }
        else {
            if ($action eq 'add') {
                osh_info "Account $Account has now access to the group key of $Group, but does NOT";
                osh_info "automatically inherits access to any of the group's servers, only to $machine,";
                osh_info "and any other(s) $Group group server(s) previously granted to $Account.";
                osh_info "This access will expire in " . OVH::Bastion::duration2human(seconds => $ttl)->value->{'human'}
                  if $ttl;
            }
            else {
                osh_info "Access to $machine through group $Group was removed from account $Account";
            }
        }

        if ($action eq 'del') {

            # if the guest group access file of this account is now empty, we should remove the account from the group
            # but ONLY if the account doesn't have regular member access to the group too.
            my $accessesFound = 0;
            if ($Account->type ne 'realm') {
                # in non-realm mode, just check the account itself
                $fnret =
                  OVH::Bastion::get_acl_way(way => 'groupguest', group => $Group->name, account => $Account->name);
                $fnret or return $fnret;
                $accessesFound += @{$fnret->value};
            }
            else {
                # in realm-mode, we need to check that all the other remote accounts no longer have access either, before removing the key
                $fnret = $Account->getRemoteAccounts();
                $fnret or return $fnret;
                foreach my $RemoteAccount (@{$fnret->value}) {
                    $fnret = OVH::Bastion::get_acl_way(
                        way     => 'groupguest',
                        group   => $Group->name,
                        account => $RemoteAccount->name,
                    );
                    OVH::Bastion::osh_debug("for $RemoteAccount, got acls: $fnret, number=".@{$fnret->value});
                    $accessesFound += @{$fnret->value};
                    last if $accessesFound > 0;
                }
            }

            if ($accessesFound == 0 && !$Group->hasMember($Account)) {
                osh_debug "No guest access remains to group $Group for account $Account, removing group key access";
                #
                # remove account from group
                #
                @command = qw{ sudo -n -u root -- /usr/bin/env perl -T };
                push @command, $OVH::Bastion::BASEPATH . '/bin/helper/osh-groupSetRole';
                push @command, '--type', 'guest';
                push @command, '--group', $Group->sysGroup;
                push @command, '--account', $Account->name;
                push @command, '--action', 'del';

                $fnret = OVH::Bastion::helper(cmd => \@command);
                $fnret or return $fnret;

                my $displayName = $Account->realm ? "realm " . $Account->realm : "account $Account";
                osh_info "No guest access to servers of group $Group remained for $displayName, removed group key access";
            }
        }
        else {
            osh_info "\nYou can view ${Account}'s guest accesses to $Group with the following command:";
            my $bastionName = OVH::Bastion::config('bastionName')->value();
            osh_info "$bastionName --osh groupListGuestAccesses --account $Account --group $Group";
        }
    }

    # don't log on OK_NO_CHANGE, only on OK
    if ($fnret->err eq 'OK') {
        OVH::Bastion::syslog_formatted(
            severity => 'info',
            type     => 'membership',
            fields   => [
                ['action',  $action],
                ['type',    $role],
                ['group',   $Group->name],
                ['account', $Account->name],
                ['self',    $Self->name],
                ['user',    $user],
                ['host',    $host],
                ['port',    $port],
                ['ttl',     $ttl],
                ['comment', $comment || ''],
            ]
        );
    }

    return $fnret;
}

1;
