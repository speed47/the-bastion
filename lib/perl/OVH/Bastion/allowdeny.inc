package OVH::Bastion;

# vim: set filetype=perl ts=4 sw=4 sts=4 et:

use common::sense;

use Socket qw{ :all };
use Hash::Util qw{ unlock_hashref_recurse };
use Memoize;

# this function simply checks if the user@ip:port is allowed in the way given,
# i.e. personal access, group access, groupguest access, or legacy access.
# it calls is_access_granted_in_file with the proper file location depending
# on the access way that is tested. note that for e.g. group accesses, we don't
# check if a given account has access to the group or not, we just check if the
# group itself has access. this check must be done by our caller.
# returns: { match, size, forceKey, forcePassword } for best match, if any
sub is_access_way_granted {
    my %p     = @_;
    my $fnret = OVH::Bastion::check_args(
        \%p,
        mandatory       => [qw{ ip way }],
        optionalFalseOk => [
            qw{ exactIpMatch exactPortMatch exactUserMatch exactMatch
              ignoreUser ignorePort user port group account }
        ],
    );
    $fnret or return $fnret;

    my $exactIpMatch = $p{'exactIpMatch'}; # $ip must be explicitly allowed (not given through a wider slash or a 0.0.0.0/0 in grantfile)
    my $exactPortMatch = $p{'exactPortMatch'}; # $port must be explicitly allowed (port wildcards in grantfile will be ignored)
    my $exactUserMatch = $p{'exactUserMatch'}; # $user must be explicitly allowed (user wildcards in grantfile will be ignored)
    my $exactMatch     = $p{'exactMatch'};     # sets exactIpMatch exactPortMatch and exactUserMatch

    my $ignoreUser = $p{'ignoreUser'};    # ignore remote user COMPLETELY (plop@, or root@, or <nil>@ will all match)
    my $ignorePort = $p{'ignorePort'};    # ignore port COMPLETELY (port 22, 2345, or port-wildcard will all match)

    my $wantedUser = $p{'user'};          # if undef, means we look for a user wildcard allow
    my $wantedIp   = $p{'ip'};            # can be a single IP or a prefix
    my $wantedPort = $p{'port'};          # if undef, means we look for a port wildcard allow

    my $way     = $p{'way'};              # personal|group|groupguest|legacy
    my $group   = $p{'group'};            # only meaningful and needed if way=group or way=groupguest
    my $account = $p{'account'};          # only meaningful and needed if way=personal or way=groupguest

    $exactIpMatch = $exactPortMatch = $exactUserMatch = 1 if $exactMatch;

    # 'group', 'account', and 'way' parameters are only useful to, and checked by, get_acl_way()
    $fnret = OVH::Bastion::get_acl_way(way => $way, account => $account, group => $group);
    $fnret or return $fnret;
    my @acl = @{$fnret->value || []};

    osh_debug(
        "checking way $way/$account/$group with ignorePort=$ignorePort ignoreUser=$ignoreUser exactIpMatch=$exactIpMatch exactPortMatch=$exactPortMatch exactUserMatch=$exactUserMatch"
    );

    my ($bestMatch, $bestMatchSize, $bestMatchComment, $forceKey, $forcePassword);
    foreach my $entry (@acl) {
        my $allowedIp          = $entry->{'ip'};              # can be a prefix
        my $allowedUser        = $entry->{'user'};            # can be undef (if any-user)
        my $allowedPort        = $entry->{'port'};            # can be undef (if any-port)
        my $localForceKey      = $entry->{'forceKey'};
        my $localForcePassword = $entry->{'forcePassword'};

        osh_debug("checking wanted "
              . (defined $wantedUser ? $wantedUser : '<u>') . '@'
              . (defined $wantedIp   ? $wantedIp   : '<u>') . ':'
              . (defined $wantedPort ? $wantedPort : '<u>')
              . ' against '
              . (defined $allowedUser ? $allowedUser : '<u>') . '@'
              . (defined $allowedIp   ? $allowedIp   : '<u>') . ':'
              . (defined $allowedPort ? $allowedPort : '<u>'));

        $allowedIp or next;    # can't be empty

        # first, check port stuff
        # if we get ignorePort, we skip the checks entirely
        if (not $ignorePort) {
            if ($exactPortMatch) {

                # we want an exact match
                if (not defined $allowedPort) {
                    if (not defined $wantedPort) {
                        ;    # both undefined ? ok
                    }
                    else {
                        next;    # if only one of two is undef, it's not an exact match
                    }
                }
                else {
                    if (not defined $wantedPort) {
                        next;    # if only one of two is undef, it's not an exact match
                    }
                    else {
                        next if ($wantedPort ne $allowedPort);    # both defined but unequal, not a match
                    }
                }
            }
            else {
                # we don't want an exact match (aka wildcards allowed)
                if (not defined $allowedPort) {
                    ;                                             # it's a wildcard, will always match
                }
                else {
                    if (not defined $wantedPort) {
                        next;                                     # we want a wildcard, but we don't have it
                    }
                    else {
                        next if ($wantedPort ne $allowedPort);    # both defined but unequal, not a match
                    }
                }
            }
        }

        # second, check user stuff
        # if we get ignoreUser, we skip the checks entirely
        if (not $ignoreUser) {
            if ($exactUserMatch) {

                # we want an exact match
                if (not defined $allowedUser) {
                    if (not defined $wantedUser) {
                        ;    # both undefined ? ok
                    }
                    else {
                        next;    # if only one of two is undef, it's not an exact match
                    }
                }
                else {
                    if (not defined $wantedUser) {
                        next;    # if only one of two is undef, it's not an exact match
                    }
                    else {
                        next if ($wantedUser ne $allowedUser);    # both defined but unequal, not a match
                    }
                }
            }
            else {
                # we don't want an exact match (aka wildcards allowed)
                if (not defined $allowedUser) {
                    ;                                             # it's a wildcard, will always match
                }
                else {
                    if (not defined $wantedUser) {
                        next;                                     # we want a wildcard, but we don't have it
                    }
                    else {
                        next if ($wantedUser ne $allowedUser);    # both defined but unequal, not a match
                    }
                }
            }
        }

        # then, check IP
        # if we want an exact match, it's a stupid strcmp()
        if ($exactIpMatch) {
            next if ($allowedIp ne $wantedIp);

            # here, we got a perfect match
            $forceKey         = $localForceKey;
            $forcePassword    = $localForcePassword;
            $bestMatch        = $allowedIp;
            $bestMatchComment = $entry->{'userComment'};
            $bestMatchSize    = undef;                     # not needed
            last;                                          # perfect match, don't search further
        }

        # check IP in not-exactIpMatch case. if it contains / then it's a prefix
        if ($allowedIp =~ m{/}) {

            # build slash and test
            require Net::Netmask;
            my $ipCheck = Net::Netmask->new2($allowedIp);
            if ($ipCheck && $ipCheck->match($wantedIp)) {
                osh_debug("... we got a slash match !");
                if (not defined $bestMatchSize or $ipCheck->size() < $bestMatchSize) {
                    $forceKey         = $localForceKey;
                    $forcePassword    = $localForcePassword;
                    $bestMatch        = $allowedIp;
                    $bestMatchComment = $entry->{'userComment'};
                    $bestMatchSize    = $ipCheck->size();
                    $bestMatchSize == 1 and last;    # we won't get better than this
                }
            }
        }
        else {
            # it's a single ip, so a stupid strcmp() does the trick
            if ($allowedIp eq $wantedIp) {
                osh_debug("... we got a singleip match !");
                $forceKey         = $localForceKey;
                $forcePassword    = $localForcePassword;
                $bestMatch        = $allowedIp;
                $bestMatchComment = $entry->{'userComment'};
                $bestMatchSize    = 1;
                last;
            }
        }
    }

    if (defined $bestMatch) {
        return R(
            'OK',
            value => {
                match         => $bestMatch,
                size          => $bestMatchSize,
                forceKey      => $forceKey,
                forcePassword => $forcePassword,
                comment       => $bestMatchComment
            }
        );
    }
    return R('KO_ACCESS_DENIED');
}

# from a given hostname, check if we have an ip or a range of ip or try to resolve
sub get_ip {
    my %p     = @_;
    my $fnret = OVH::Bastion::check_args(
        \%p,
        mandatory       => [qw{ host }],
        optionalFalseOk => [qw{ v4 v6 }],
    );
    $fnret or return $fnret;

    my $host = $p{'host'};
    my $v4   = $p{'v4'};     # allow ipv4 ?
    my $v6   = $p{'v6'};     # allow ipv6 ?

    # by default, only v4 unless specified otherwise
    $v4 = 1 if not defined $v4;
    $v6 = 0 if not defined $v6;

    # try to see if it's already an IP
    osh_debug("checking if '$host' is already an IP");
    $fnret = OVH::Bastion::is_valid_ip(ip => $host, allowPrefixes => 0);
    if ($fnret) {
        osh_debug("Host $host is already an IP");
        if (   ($fnret->value->{'version'} == 4 && $v4)
            || ($fnret->value->{'version'} == 6 && $v6))
        {
            return R('OK', value => {ip => $fnret->value->{'ip'}, iplist => [$fnret->value->{'ip'}]});
        }
        return R('ERR_INVALID_IP', msg => "IP $host version is not allowed");
    }

    osh_debug("Trying to resolve '$host' because is_valid_ip() says it's not an IP");
    my ($err, @res);
    eval {
        # dns resolving, v4/v6 compatible
        # can croak
        ($err, @res) = getaddrinfo($host, undef, {socktype => SOCK_STREAM});
    };
    return R('ERR_HOST_NOT_FOUND', msg => $@)   if $@;
    return R('ERR_HOST_NOT_FOUND', msg => $err) if $err;

    my %iplist;
    my $lastip;
    foreach my $item (@res) {
        if ($item->{'family'} == AF_INET) {
            next if not $v4;
        }
        elsif ($item->{'family'} == AF_INET6) {
            next if not $v6;
        }
        else {
            # unknown weird family ?
            next;
        }
        my $as_text;
        undef $err;
        eval {
            ($err, $as_text) = getnameinfo($item->{'addr'}, NI_NUMERICHOST); # NI flag: don't use dns, just unpack the binary 'addr'
        };
        if (not $@ and not $err) {
            $iplist{$as_text} = 1;
            $lastip = $as_text;
        }
    }

    if (%iplist) {
        return R('OK', value => {ip => $lastip, iplist => [keys %iplist]});
    }

    # %iplist empty, not resolved (?)
    return R('ERR_HOST_NOT_FOUND', msg => "Unable to resolve '$host'");
}

# reverse-dns of an IPv4 or IPv6
sub ip2host {
    my ($ip, %p) = @_;
    $p{'ip'} = $ip;
    my $fnret = OVH::Bastion::check_args(\%p, mandatory => [qw{ ip }]);
    $fnret or return $fnret;

    my ($err, @sockaddr, $host);

    eval {
        # ip => packedip. AI_PASSIVE: don't use dns, just build sockaddr
        # can croak
        ($err, @sockaddr) = getaddrinfo($ip, 0, {flags => AI_PASSIVE, socktype => SOCK_STREAM});
    };
    return R('ERR_INVALID_IP', msg => $@)   if $@;
    return R('ERR_INVALID_IP', msg => $err) if $err;

    eval {
        # can croak
        ($err, $host, undef) = getnameinfo($sockaddr[0]->{'addr'}, NI_NAMEREQD);
    };
    return R('ERR_HOST_NOT_FOUND', msg => $@)   if $@;
    return R('ERR_HOST_NOT_FOUND', msg => $err) if $err;

    return R('OK', value => $host);
}

sub get_pub_keys_from_directory {
    my %p     = @_;
    my $fnret = OVH::Bastion::check_args(
        \%p,
        mandatory       => [qw{ dir }],
        optional        => [qw{ pattern }],
        optionalFalseOk => [qw{ listOnly noexec forceKey wantPrivate }],
    );
    $fnret or return $fnret;

    my $dir         = $p{'dir'};
    my $pattern     = $p{'pattern'};
    my $listOnly    = $p{'listOnly'};       # don't open the files, just return file names
    my $noexec      = $p{'noexec'};         # passed to is_valid_public_key
    my $forceKey    = $p{'forceKey'};
    my $wantPrivate = $p{'wantPrivate'};    # if set, will return the fullpath of the private key, not the public one

    osh_debug("looking for pub keys in dir $dir as user $ENV{'USER'}");
    if (!-d $dir) {
        return R('ERR_DIRECTORY_NOT_FOUND', msg => "directory $dir doesn't exist");
    }
    my $dh;
    if (!opendir($dh, $dir)) {
        return R('ERR_CANNOT_OPEN_DIRECTORY', msg => "can't open directory $dir: $!");
    }

    if (defined $pattern and ref $pattern ne 'Regexp') {
        return R('ERR_INVALID_PARAMETER', msg => 'pattern is not a Regexp reference');
    }

    my %return;
    while (my $file = readdir($dh)) {
        $file =~ /^([a-zA-Z0-9._-]+\.pub)$/ or next;
        $file = $1;    # untaint
        if (defined $pattern) {
            $file =~ /$pattern/ or next;
        }
        my $filename = $file;
        $file = "$dir/$file";
        -f -r $file or next;

        # ok file exists, is readable and matches the pattern
        osh_debug("file $file matches the pattern in $dir");

        my $mtime = (stat(_))[9];
        if ($listOnly) {
            $return{$file} = {fullpath => $file, filename => $filename, mtime => $mtime};
            if ($wantPrivate) {
                $return{$file}{'fullpath'} =~ s/\.pub$//;
                $return{$file}{'filename'} =~ s/\.pub$//;
            }
        }
        else {
            # open the file and read the key
            my $fh_key;
            if (!open($fh_key, '<', $file)) {
                osh_debug("can't open file $file ($!), skipping");
                next;
            }

            while (my $line = <$fh_key>) {

                # stop when we find a key or at EOF
                chomp $line;
                $fnret = OVH::Bastion::is_valid_public_key(
                    way    => 'egress',
                    pubKey => $line,
                    noexec => ($noexec && !$forceKey)
                );
                if (!$fnret) {
                    osh_debug("key in $file is not valid: " . $fnret->err);
                    osh_debug($fnret->msg);
                }
                else {
                    if ((not defined $forceKey) || ($forceKey eq $fnret->value->{'fingerprint'})) {
                        $return{$file}             = unlock_hashref_recurse($fnret->value);
                        $return{$file}{'fullpath'} = $file;
                        $return{$file}{'mtime'}    = $mtime;
                        $return{$file}{'filename'} = $filename;
                        if ($wantPrivate) {
                            $return{$file}{'fullpath'} =~ s/\.pub$//;
                            $return{$file}{'filename'} =~ s/\.pub$//;
                        }
                    }
                    last;
                }
            }
            close($fh_key);
        }
    }
    close($dh);

    # return a sorted keys list too f(mtime) desc
    my @sortedKeys = sort { $return{$b}{'mtime'} <=> $return{$a}{'mtime'} } keys %return;
    return R('OK', value => {keys => \%return, sortedKeys => \@sortedKeys});
}

sub duration2human {
    my %p     = @_;
    my $fnret = OVH::Bastion::check_args(
        \%p,
        mandatory       => [qw{ seconds }],
        optionalFalseOk => [qw{ tense }],
    );
    $fnret or return $fnret;

    my $s     = $p{'seconds'};
    my $tense = $p{'tense'} || '';

    require POSIX;
    my $date_local = POSIX::strftime("%a %Y-%m-%d %H:%M:%S %Z", localtime(time() + ($tense eq 'past' ? -$s : $s)));
    my $date_utc = POSIX::strftime("%a %Y-%m-%d %H:%M:%S UTC", gmtime(time() + ($tense eq 'past' ? -$s : $s)));

    my $d = int($s / 86400);
    $s -= $d * 86400;
    my $h = int($s / 3600);
    $s -= $h * 3600;
    my $m = int($s / 60);
    $s -= $m * 60;

    my $duration = $d ? sprintf('%dd+%02d:%02d:%02d', $d, $h, $m, $s) : sprintf('%02d:%02d:%02d', $h, $m, $s);

    # we keep the 'date' key for backwards compat, it's the same as 'datetime_local'
    return R(
        'OK',
        value => {
            duration       => $duration,
            date           => $date_local,
            datetime_local => $date_local,
            datetime_utc   => $date_utc,
            human          => "$duration ($date_local)"
        }
    );
}

sub print_acls {
    my %p     = @_;
    my $fnret = OVH::Bastion::check_args(
        \%p,
        mandatory       => [qw{ acls }],
        optionalFalseOk => [qw{ reverse hideGroups includes excludes }],
    );
    $fnret or return $fnret;

    my $acls       = $p{'acls'} || [];
    my $reverse    = $p{'reverse'};
    my $hideGroups = $p{'hideGroups'};
    my $includes   = $p{'includes'} || [];
    my $excludes   = $p{'excludes'} || [];

    my $includere = OVH::Bastion::build_re_from_wildcards(wildcards => $includes, implicit_contains => 1)->value;
    my $excludere = OVH::Bastion::build_re_from_wildcards(wildcards => $excludes, implicit_contains => 1)->value;

    # first, get all the rows we'll print, and fill both the array that will be printed (printRows),
    # and the one that will be returned as JSON (jsonRows). We also apply the filters here to include/exclude
    # the requested patterns, if any
    # also take this opportunity to remember the longest field for each column
    my @printRows;
    my @jsonRows;
    my @columnNames       = qw( IP PORT USER ACCESS-BY ADDED-BY ADDED-AT EXPIRY? COMMENT FORCED-KEY FORCED-PASSWORD);
    my @printColumnLength = map { length } @columnNames;
    foreach my $contextAcl (@$acls) {
        my $type  = $contextAcl->{'type'};
        my $group = $contextAcl->{'group'};
        my $acl   = $contextAcl->{'acl'};

        next if ($hideGroups and $type =~ /^group/);
        my $accessType = ($group ? "$group($type)" : $type);

      ENTRY: foreach my $entry (@$acl) {
            my $addedBy   = $entry->{'addedBy'}   || '-';
            my $addedDate = $entry->{'addedDate'} || '-';
            $addedDate = substr($addedDate, 0, 10);
            my $forceKey      = $entry->{'forceKey'}      || '-';
            my $forcePassword = $entry->{'forcePassword'} || '-';
            my $expiry =
              $entry->{'expiry'} ? (duration2human(seconds => ($entry->{'expiry'} - time()))->value->{'human'}) : '-';

            # resolve reverse if asked for it
            my $ipReverse;
            $ipReverse = OVH::Bastion::ip2host($entry->{'ip'})->value if $reverse;
            $entry->{'reverseDns'} = $ipReverse;

            my @row = (
                $ipReverse ? $ipReverse : $entry->{'ip'}, $entry->{'port'} ? $entry->{'port'} : '(any)',
                $entry->{'user'} ? $entry->{'user'} : '(any)', $accessType,
                $addedBy,  $addedDate,
                $expiry,   $entry->{'userComment'} || '-',
                $forceKey, $forcePassword
            );

            # if we have includes or excludes, match fields against the built regex
            # for excludes, any field matching is enough to exclude the row
            if ($excludere) {
                foreach (@row) {
                    next ENTRY if ($_ =~ $excludere);
                }
            }

            # for includes, at least one field must match or we exclude the row
            if ($includere) {
                my $matched = 0;
                foreach (@row) {
                    $matched++ if ($_ =~ $includere);
                    last if $matched;
                }
                next ENTRY if !$matched;
            }

            # if we're here, row must be included
            push @printRows, \@row;
            push @jsonRows,  $entry;

            # for each cell of this row, remember its len if its longer than any previously seen cell in the same column
            for (0 .. @row) {
                my $cellLen = length($row[$_]);
                $printColumnLength[$_] = $cellLen if $printColumnLength[$_] < $cellLen;
            }
        }
    }

    # then, check if we have at least one non-empty row for each column,
    # so that we can omit the empty columns on print (empty cells are '-')
    my %atLeastOne;
    foreach my $row (@printRows) {
        my $i = 0;
        foreach my $cell (@$row) {
            $atLeastOne{$i}++ if $cell ne '-';
            $i++;
        }
    }

    # now build the header
    my (@header, @format, @underline);
    my $i = 0;
    foreach (@columnNames) {
        if ($atLeastOne{$i}) {
            push @header,    $_;
            push @format,    "%" . ($printColumnLength[$i] + 0) . "s";
            push @underline, "-" x ($printColumnLength[$i] + 0);
        }
        $i++;
    }
    my $formatstr = join(" ", @format);
    osh_info(sprintf($formatstr, @header));
    osh_info(sprintf($formatstr, @underline));

    # and print each row, potentially omitting empty columns (%atLeastOne)
    foreach my $row (@printRows) {
        my @fields;
        $i = 0;
        foreach my $cell (@$row) {
            push @fields, $cell if ($atLeastOne{$i});
            $i++;
        }
        osh_info(sprintf($formatstr, @fields));
    }
    osh_info("\n" . scalar(@printRows) . " accesses listed");
    return R('OK', value => \@jsonRows);
}

# checks if ip matches any given array of prefixes/networks
memoize('_is_in_any_net');

sub _is_in_any_net {
    my %p     = @_;
    my $fnret = OVH::Bastion::check_args(
        \%p,
        mandatory => [qw{ ip }],
        optional  => [qw{ networks }],
    );
    $fnret or return $fnret;

    my $ip       = $p{'ip'};
    my $networks = $p{'networks'};

    if (ref $networks ne 'ARRAY') {
        return R('ERR_INVALID_PARAMETER', msg => "Parameter 'networks' must be an array");
    }

    foreach my $net (@$networks) {
        if ($net =~ m{/}) {
            # build slash and test
            require Net::Netmask;
            my $ipCheck = Net::Netmask->new2($net);
            return R('OK', value => {matched => $net}) if ($ipCheck && $ipCheck->match($ip));
        }
        else {
            # it's a single ip, so it's a stupid strcmp() does the trick
            return R('OK', value => {matched => $net}) if ($net eq $ip);
        }
    }
    return R('KO', msg => "No match found");
}

# this function checks if the given account has access to user@ip:port
# through any of the supported ways (personal/group/guest/legacy accesses),
# by calling is_access_way_granted() multiple times with the proper params.
# it can also add the fullpath of the keys to try for allowed accesses if asked to
# returns: arrayref of contextualized grants, contextualized-grant: { type, group, $granthashref }
# granthashref: returned by is_access_way_granted, i.e. { match, size, forceKey, forcePassword }
sub is_access_granted {
    my %params = @_;

    # we'll use delete for params that we won't pass through is_access_way_granted()
    my $account = delete $params{'account'};    # account to check the access grants of.
                                                # can also be of the format "realm/remoteself"

    my $ipfrom = delete $params{'ipfrom'};      # must be an IP (client IP)
    my $ip     = $params{'ip'};                 # can be a single IP or a slash
    my $port   = $params{'port'};               # if undef, means we look for a port wildcard allow
    my $user   = $params{'user'};               # if undef, means we look for a user wildcard allow

    my $listOnly = delete $params{'listOnly'};  # don't open the files, just return file names
    my $noexec   = delete $params{'noexec'};    # passed to is_valid_public_key

    my $details = delete $params{'details'}; # if set, look for and return ssh keys + config data along with allowed accesses

    delete $params{'way'};                   # WE specify this parameter, not our caller
    delete $params{'group'};                 # WE specify this parameter, not our caller

    my @grants;
    my $fnret;
    require Data::Dumper;

    # 0a/3 check if we're in a forbidden network. if we are, just bail out
    my $forbiddenNetworks = OVH::Bastion::config('forbiddenNetworks')->value;
    $fnret = _is_in_any_net(ip => $ip, networks => $forbiddenNetworks);
    return R('KO_ACCESS_DENIED',
        msg => "Can't connect you to $ip as it's part of the forbidden networks of this bastion (see --osh info)")
      if $fnret->is_ok;

    # 0b/3 check if we're not outside of the bastion allowed networks, if we are, just bail out
    my $allowedNetworks = OVH::Bastion::config('allowedNetworks')->value;
    if (@$allowedNetworks) {
        $fnret = _is_in_any_net(ip => $ip, networks => $allowedNetworks);
        return R('KO_ACCESS_DENIED',
            msg => "Can't connect you to $ip as it's not part of the allowed networks of this bastion (see --osh info)")
          if $fnret->is_ko;
    }

    # 0c/3 check if there are more complex "ingressToEgressRules" defined, and potentially bail out whether needed
    $fnret = OVH::Bastion::config('ingressToEgressRules');
    my @rules = @{$fnret->value || []};
    foreach my $ruleNb (0 .. $#rules) {
        my ($inNets, $outNets, $policy) = @{$rules[$ruleNb]};

        $fnret = _is_in_any_net(ip => $ipfrom, networks => $inNets);
        if ($fnret->is_err) {
            warn("Denied access due to potential configuration error in ingressToEgressRules (rule #$ruleNb, ingress");
            return R('KO_ACCESS_DENIED', msg => "Error checking ingressToEgressRules, warn your bastion admin!");
        }

        # ingress IP doesn't match for this rule, go to next:
        next if $fnret->is_ko;

        # ingress IP matches, check whether egress IP matches
        $fnret = _is_in_any_net(ip => $ip, networks => $outNets);
        if ($fnret->is_err) {
            warn("Denied access due to potential configuration error in ingressToEgressRules (rule #$ruleNb, egress");
            return R('KO_ACCESS_DENIED', msg => "Error checking ingressToEgressRules, warn your bastion admin!");
        }
        if ($policy eq 'ALLOW-EXCLUSIVE') {
            if ($fnret->is_ok) {

                # egress matches: allowed, stop checking more rules
                last;
            }

            # is_ko: we're in exclusive mode, stop checking and deny
            return R('KO_ACCESS_DENIED',
                msg =>
                  "Can't connect you to $ip, as it's not part of the allowed networks given where you're connecting from ($ipfrom)"
            );
        }
        elsif ($policy eq 'DENY') {
            if ($fnret->is_ok) {

                # egress matches: we have been asked to deny
                return R('KO_ACCESS_DENIED',
                    msg =>
                      "Can't connect you to $ip, as it's not part of the allowed networks given where you're connecting from ($ipfrom)"
                );
            }

            # is_ko: egress doesn't match, check next rule
        }
        elsif ($policy eq 'ALLOW') {
            if ($fnret->is_ok) {

                # egress matches: we have been asked to allow, stop checking more rules
                last;
            }

            # is_ko: egress doesn't match, check next rule
        }
        else {
            # invalid policy
            warn("Denied access due to potential configuration error in ingressToEgressRules (rule #$ruleNb, policy");
            return R('KO_ACCESS_DENIED', msg => "Error checking ingressToEgressRules, warn your bastion admin!");
        }
    }

    my $Account = OVH::Bastion::Account->newFromName($account, check => 1);
    $Account or return $Account;

    # 1/3 check for personal accesses
    # ... normal way
    my $grantedPersonal = is_access_way_granted(%params, way => 'personal', account => $account);
    osh_debug("is_access_granted: grantedPersonal=" . Data::Dumper::Dumper($grantedPersonal));
    push @grants, {type => 'personal', %{$grantedPersonal->value}} if $grantedPersonal;

    # ... legacy way
    my $grantedLegacy = is_access_way_granted(%params, way => 'legacy', account => $account);
    osh_debug("is_access_granted: grantedLegacy=" . Data::Dumper::Dumper($grantedLegacy));
    push @grants, {type => 'personal-legacy', %{$grantedLegacy->value}} if $grantedLegacy;

    # 2/3 check groups
    $fnret = $Account->getGroups();
    my $groups = $fnret->value || {};
    osh_debug("is_access_granted: get_user_groups of $Account says "
          . $fnret->msg
          . " with grouplist "
          . Data::Dumper::Dumper($groups));

    foreach my $group (sort keys %$groups) {
        my $Group = OVH::Bastion::Group->newFromName($group, check => 1);
        $Group or next;

        # then check for group access
        my $grantedGroup = is_access_way_granted(%params, way => "group", group => $Group->name);
        osh_debug("is_access_granted: grantedGroup=" . Data::Dumper::Dumper($grantedGroup));
        next if not $grantedGroup;            # if group doesn't have access, don't even check legacy either

        # now we have to cases, if the group has access: either the account is member or guest
        if ($groups->{$Group->name}{'member'}) {

            # normal member case, just reuse $grantedGroup
            osh_debug("is_access_granted: adding grantedGroup to grants because is member");
            push @grants, {type => 'group-member', group => $Group->name, %{$grantedGroup->value}};
        }
        elsif ($groups->{$Group->name}{'guest'}) {

            # normal guest case
            my $grantedGuest =
              is_access_way_granted(%params, way => "groupguest", group => $Group->name, account => $account);
            osh_debug("is_access_granted: grantedGuest=" . Data::Dumper::Dumper($grantedGuest));

            # the guy must have a guest access but the group itself must also still have access
            if ($grantedGuest && $grantedGroup) {
                push @grants, {type => 'group-guest', group => $Group->name, %{$grantedGuest->value}};
                osh_debug("is_access_granted: adding grantedGuest to grants because is guest and group has access");
            }

            # special legacy case; we also check if account has a legacy access for ip AND that the group ALSO has access to this ip
            if ($grantedLegacy && $grantedGroup) {
                osh_debug(
                    "is_access_granted: adding grantedLegacy to grants because legacy not null and group has access");
                push @grants, {type => 'group-guest-legacy', group => $Group->name, %{$grantedLegacy->value}};
            }
        }
        else {
            # has another role (aclkeeper, gatekeeper, owner) => no access through this group
            osh_debug("is_access_granted: $account has a role in group $Group but is neither member or guest");
        }
    }

    # 3/3 fill up keys and other metadata info (mfa, idle lock/kill timeout) if asked to
    if ($details) {
        foreach my $access (@grants) {
            my %data;
            if ($access->{'type'} =~ /^group/ and $access->{'group'}) {
                my $Group = OVH::Bastion::Group->newFromName($access->{'group'}, check => 1); # FIXME we should use cache here
                $Group or next;
                $data{'keys'} = $Group->getKeys(
                        listOnly => $listOnly,
                        noexec   => $noexec,
                        forceKey => $access->{'forceKey'}
                );
                $data{'mfa'} = $Group->getConfig("mfa_required");
                $data{'idle_lock_timeout'} = $Group->getConfig("idle_lock_timeout");
                $data{'idle_kill_timeout'} = $Group->getConfig("idle_kill_timeout");
            }
            elsif ($access->{'type'} =~ /^personal/) {
                $data{'keys'} = $Account->getPersonalKeys(
                    listOnly => $listOnly,
                    noexec   => $noexec,
                    forceKey => $access->{'forceKey'}
                );
                $data{'mfa'} = $Account->getConfig("private/personal_egress_mfa_required");
            }
            else {
                # unknown access type? no key!
                warn_syslog("Unknown access type '" . $access->{'type'} . "' found, ignoring");
            }
            if ($data{'keys'}) {

                # TODO implement $access->{forceKey} check to include only the proper key
                $access->{'keys'}            = $data{'keys'}->value->{'keys'};
                $access->{'sortedKeys'}      = $data{'keys'}->value->{'sortedKeys'};
                $access->{'mfaRequired'}     = $data{'mfa'}->value if $data{'mfa'};
                $access->{'idleLockTimeout'} = $data{'idle_lock_timeout'}->value if $data{'idle_lock_timeout'};
                $access->{'idleKillTimeout'} = $data{'idle_kill_timeout'}->value if $data{'idle_kill_timeout'};
            }
        }
    }

    return R('OK', value => \@grants) if @grants;

    my $machine = $ip;
    $machine .= ":$port" if $port;
    $machine = $user . '@' . $machine if $user;
    return R('KO_ACCESS_DENIED', msg => "Access denied for $account to $machine");
}

sub ssh_test_access_way {
    my %params  = @_;
    my $account = $params{'account'};
    my $group   = $params{'group'};

    my $port = $params{'port'};
    my $ip   = $params{'ip'};
    my $user = $params{'user'};
    my $fnret;

    if (defined $account and defined $group) {
        return R('ERR_INCOMPATIBLE_PARAMETERS');
    }

    $fnret = OVH::Bastion::is_valid_ip(ip => $ip, allowPrefixes => 1);
    $fnret or return $fnret;
    if ($fnret->value->{'type'} eq 'prefix') {
        return R('OK_PREFIX', msg => "Can't test a connection to a prefix, assuming it's OK");
    }
    $ip = $fnret->value->{'ip'};

    if ($port) {
        $fnret = OVH::Bastion::is_valid_port(port => $port);
        $fnret or return $fnret;
        $port = $fnret->value;
    }

    $user = OVH::Bastion::config("defaultLogin")->value if not $user;
    $user = $account                                    if not $user;    # defaultLogin empty means the user himself
    $user = OVH::Bastion::get_user_from_env()->value    if not $user;    # no user or account ? get from env then
    $fnret = OVH::Bastion::is_valid_remote_user(user => $user);
    $fnret or return $fnret;
    $user = $fnret->value;

    my $Account;
    my $Group;
    if ($group) {
        $Group = OVH::Bastion::Group->newFromName($group, check => 1);
        $Group or return $Group;

        $fnret = $Group->getKeys();
    }
    elsif ($account) {
        $Account = OVH::Bastion::Account->newFromName($account, check => 1);
        $Account or return $Account;

        $fnret = $Account->getPersonalKeys();
    }
    else {
        return R('ERR_MISSING_PARAMETER', msg => "Missing 'group' or 'account' for ssh_test_access_way");
    }
    $fnret or return $fnret;

    my @keyList;
    foreach my $keyfile (@{$fnret->value->{'sortedKeys'}}) {
        my $key     = $fnret->value->{'keys'}{$keyfile};
        my $privkey = $key->{'fullpath'};
        $privkey =~ s/\.pub$//;
        push @keyList, $privkey if -r $privkey;
    }

    if (not @keyList) {
        return R('OK_NO_KEYS_TO_TEST',
            msg =>
              "Couldn't find any accessible SSH key to test connection with, you're probably adding access to an account or a group you don't have access to yourself, nevermind, will continue"
        );
    }

    if ($user eq '!scpupload' || $user eq '!scpdownload') {
        return R('OK_MAGIC_USER', msg => "Didn't really test the connection, as the specified user is special");
    }

    my $preferredAuthentications = 'publickey';
    $preferredAuthentications .= ',keyboard-interactive' if $ENV{'OSH_KBD_INTERACTIVE'};

    # ssh -i with the correct keys
    # UserKnownHostsFile/StrictHostKeyChecking: avoid problem when opening /dev/tty under sudo
    my @command = qw{ ssh -o ConnectTimeout=5 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no };
    push @command, '-o', 'PreferredAuthentications=' . $preferredAuthentications;
    foreach (@keyList) {
        push @command, "-i", $_;
    }
    if (!OVH::Bastion::is_openbsd()) {
        unshift @command, qw{ timeout -k 1 6 };
    }

    # add port when specified
    push @command, ("-p", $port) if $port;

    push @command, "-l", $user, $ip, '-T', '--', 'true';

    osh_info("Testing connection to $user\@$ip, please wait...");
    # in case the remote server happens to be a bastion too, and the account we're
    # testing is a realm support account there, we need to set LC_BASTION or the remote
    # bastion won't be happy
    if ($user =~ /^realm_/ && !$ENV{'LC_BASTION'}) {
        local $ENV{'LC_BASTION'} = OVH::Bastion::get_user_from_env()->value;
        $fnret = OVH::Bastion::execute(cmd => \@command, noisy_stderr => 1);
    }
    else {
        $fnret = OVH::Bastion::execute(cmd => \@command, noisy_stderr => 1);
    }
    $fnret or return $fnret;

    if (grep { $fnret->value->{'sysret'} eq $_ }
        (0, OVH::Bastion::EXIT_ACCOUNT_INVALID(), OVH::Bastion::EXIT_HOST_NOT_FOUND()))
    {
        return R('OK');
    }

    my $hint;

    # 124 is the return code from the timeout system command when it times out
    # tested on Linux, NetBSD
    if ($fnret->value->{'sysret'} == 124 || grep { /timed out/i } @{$fnret->value->{'stderr'} || []}) {
        $hint = "Hint: did you remotely allow this bastion to access the SSH port?";
    }
    elsif (grep { /Permission denied/i } @{$fnret->value->{'stderr'} || []}) {
        $hint = "Hint: did you add the proper public key to the remote's authorized_keys?";
    }
    my $msg = "Couldn't connect to $user\@$ip (ssh returned error " . $fnret->value->{'sysret'} . ")";
    $msg .= ". $hint" if defined $hint;

    return R('ERR_CONNECTION_FAILED', msg => $msg);
}

# this function simply returns the requested acl
# i.e. personal or legacy access of an account, group access, or groupguest access.
# it just calls get_acl_from_file() with the proper file location
# returns: arrayref of entries, entry: { ip,user,port,forceKey,forcePassword,addedBy,addedDate,comment }
memoize('get_acl_way');
sub get_acl_way {
    my %params  = @_;
    my $way     = delete $params{'way'};        # personal|group|groupguest|legacy
    my $group   = delete $params{'group'};      # only meaningful and needed if type=group or type=groupguest
    my $account = delete $params{'account'};    # only meaningful and needed if type=personal or type=groupguest

    my $fnret;
    my $Account;
    my $Group;
    my $prefix = 'allowed';

    return R('ERR_MISSING_PARAMETER', msg => "Missing argument 'way'") if not defined $way;

    osh_debug("get_acl_way with account=$account group=$group way=$way");

    if ($account) {
        $Account = OVH::Bastion::Account->newFromName($account, check => 1);
        $Account or return $Account;
        $prefix = "allowed_" . $Account->remoteName if $Account->remoteName;
    }

    if ($group) {
        $Group = OVH::Bastion::Group->newFromName($group, check => 1);
        $Group or return $Group;
    }

    if ($way eq 'personal') {
        return R('ERR_MISSING_PARAMETER', msg => "Missing parameter 'account' for $way way") if !$Account;
        if (OVH::Bastion::is_mocking()) {
            return _get_acl_from_file(
                mock_data => OVH::Bastion::mock_get_account_personal_accesses(account => $Account->name));
        }
        if (!(-f -r $Account->allowedPrivateFile)) {
            return R('ERR_PERMISSION_DENIED',
                msg => "Couldn't open permission file with your current rights or it doesn't exist");
        }
        return _get_acl_from_file(file => $Account->allowedPrivateFile);
    }
    elsif ($way eq 'legacy') {
        return R('ERR_MISSING_PARAMETER', msg => "Missing parameter 'account' for $way way") if not $account;
        if (OVH::Bastion::is_mocking()) {
            return _get_acl_from_file(mock_data =>
                OVH::Bastion::mock_get_account_legacy_accesses(account => $Account->name));
        }
        if (-f $Account->allowedPrivateFile && !-e $Account->allowedIpFile) {
            # legacy file doesn't exist: no legacy rights
            return R('OK_EMPTY', value => []);
        }
        elsif (!(-f -r $Account->allowedIpFile)) {
            return R('ERR_PERMISSION_DENIED',
                msg => "Couldn't open permission file with your current rights or it doesn't exist");
        }
        else {
            return _get_acl_from_file(file => $Account->allowedIpFile);
        }
    }
    elsif ($way eq 'group') {
        return R('ERR_MISSING_PARAMETER', msg => "Missing parameter 'group' for $way way") if not $group;
        if (OVH::Bastion::is_mocking()) {
            return _get_acl_from_file(mock_data => OVH::Bastion::mock_get_group_accesses(group => $group));
        }
        if (!(-f -r $Group->allowedIpFile)) {
            return R('ERR_PERMISSION_DENIED',
                msg => "Couldn't open permission file with your current rights or it doesn't exist");
        }
        return _get_acl_from_file(file => $Group->allowedIpFile);
    }
    elsif ($way eq 'groupguest') {
        if (!$group || !$account) {
            return R('ERR_MISSING_PARAMETER', msg => "Missing parameter 'account' or 'group' for $way way")
        }
        if (OVH::Bastion::is_mocking()) {
            return _get_acl_from_file(mock_data =>
                OVH::Bastion::mock_get_account_guest_accesses(group => $Group->name, account => $Account->name));
        }
        if (-f $Account->allowedPrivateFile
            && !-e $Account->allowedGuestFile($Group))
        {
            # guest file doesn't exist: no guest rights
            return R('OK_EMPTY', value => []);
        }
        elsif (!(-f -r $Account->allowedGuestFile($Group))) {
            return R('ERR_PERMISSION_DENIED',
                msg => "Couldn't open permission file with your current rights or it doesn't exist");
        }
        else {
            return _get_acl_from_file(file => $Account->allowedGuestFile($Group));
        }
    }

    return R('ERR_INVALID_PARAMETER',
        msg => "Expected a parameter way with allowed values [personal,legacy,group,groupguest]");
}

# returns the parsed contents of an allowkeeper-style file
sub _get_acl_from_file {
    my %params    = @_;
    my $file      = $params{'file'};
    my $mock_data = $params{'mock_data'};

    my $fnret;
    my @lines;

    if ($mock_data) {
        die "attempted to mock_data outside of mocking" if !OVH::Bastion::is_mocking();
        @lines = @$mock_data;
    }
    else {
        osh_debug("Reading ACL from '$file'");

        if (not $file) {
            return R('ERR_MISSING_PARAMETER', msg => "Missing parameter 'file'");
        }
        if (!(-e $file)) {
            return R('ERR_CANNOT_OPEN_FILE', msg => "File '$file' doesn't exist");
        }
        if (!(-r _)) {
            return R('ERR_CANNOT_OPEN_FILE', msg => "File '$file' is not readable");
        }

        if (open(my $fh_file, '<', $file)) {
            @lines = <$fh_file>;
            close($fh_file);
            chomp @lines;
        }
        else {
            return R('ERR_CANNOT_OPEN_FILE', msg => "Can't open '$file' for read ($!)");
        }
    }

    my @entries;
    foreach my $line (@lines) {
        my (
            $ip,     $user,    $port,      $comment, $forceKey, $forcePassword,
            $expiry, $addedBy, $addedDate, $extra,   $comment,  $userComment
        );

        # extract comment if any
        $line =~ s/(#.*)// and $comment = $1;

        # remove white spaces
        $line =~ s/\s//g;

        # empty line ?
        $line or next;

        # extract custom port if present
        if ($line =~ s/:(\d+)$//) {
            $fnret = OVH::Bastion::is_valid_port(port => $1);
            if (!$fnret) {
                osh_debug("skipping line <$line> because port ($1) is invalid");
                next;
            }
            $port = $fnret->value;
        }

        # extract custom user if present
        if ($line =~ s/^(\S+)\@//) {
            $fnret = OVH::Bastion::is_valid_remote_user(user => $1);
            if (!$fnret) {
                osh_debug("skipping line <$line> because user ($1) is invalid");
                next;
            }
            $user = $fnret->value;
        }

        # extract ip (v4 or v6)
        if ($line =~ m{([0-9a-f./:]+)}i) {
            $fnret = OVH::Bastion::is_valid_ip(ip => $1, allowPrefixes => 1, fast => 1);
            if (!$fnret) {
                osh_debug("skipping line <$line> because IP ($1) is invalid");
                next;
            }
            $ip = $fnret->value->{'ip'};
        }
        else {
            osh_debug("skipping line <$line> because no valid IP found");
            next;
        }

        # if we have a comment, there might be stuff to extract from it
        if (defined $comment) {
            osh_debug("Parsing comment ($comment)");
            if ($comment =~ s/# EXPIRY=(\d+)//) {
                if ($1 < time()) {
                    osh_debug("found an expired line <$line>, skipping it");
                    next;
                }
                $expiry = $1 + 0;
            }
            if ($comment =~ s/# FORCEKEY=(\S+)//) {
                $fnret = OVH::Bastion::is_valid_fingerprint(fingerprint => $1);
                if (!$fnret) {
                    osh_debug("skipping line <$line> because invalid forcekey fingerprint ($1) found");
                    next;
                }
                $forceKey = $fnret->value->{'fingerprint'};
                osh_debug("found a valid forced key <$forceKey>");
            }
            if ($comment =~ s/# FORCEPASSWORD=(\S+)//) {
                $fnret = OVH::Bastion::is_valid_hash(hash => $1);
                if (!$fnret) {
                    osh_debug("skipping line <$line> because invalid forcepassword hash ($1) found");
                    next;
                }
                $forcePassword = $fnret->value->{'hash'};
                osh_debug("found a valid forced password <$forcePassword>");
            }
            if ($comment =~ s/# COMMENT=<([^>]+)>//) {
                $userComment = $1;
            }
            if ($comment =~ s/# add(ed)? by (\S+) on (\S+ \S+)//) {
                $addedBy   = $2;
                $addedDate = $3;
            }
            $comment !~ /^\s*$/ and $extra = $comment;
        }

        push @entries,
          {
            ip            => $ip,
            user          => $user,
            port          => $port,
            forceKey      => $forceKey,
            forcePassword => $forcePassword,
            expiry        => $expiry,
            addedBy       => $addedBy,
            addedDate     => $addedDate,
            userComment   => $userComment,
            comment       => $extra,
          };
    }

    osh_debug("found " . (scalar @entries) . " valid entries");
    return R(@entries ? 'OK' : 'OK_EMPTY', value => \@entries);
}

1;
