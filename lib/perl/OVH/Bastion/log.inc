# vim: set filetype=perl ts=4 sw=4 sts=4 et:
package OVH::Bastion;

use common::sense;

use DBD::SQLite;
use Time::HiRes;
use Sys::Syslog qw();
use JSON;

my $_syslog_inited = 0;    # lazy init

sub syslog {
    my ($criticity, $message) = @_;

    if (not OVH::Bastion::config('enableSyslog')->value()) {
        return 1;          # don't do anything
    }

    if (not $_syslog_inited) {
        $_syslog_inited = 1;
        Sys::Syslog::openlog(OVH::Bastion::config('syslogDescription')->value(),
            'nofatal', OVH::Bastion::config('syslogFacility')->value());
    }

    # if message is tainted, forcefully untaint it
    # or we'll crash and we won't even log that
    # we crashed because it's tainted so we would
    # crash trying to log the crash
    ($message) = $message =~ /^(.*)$/;
    eval { Sys::Syslog::syslog($criticity, $message); };
    if ($@) {
        osh_warn("Couldn't syslog, report to administrator ($@)");
    }
    return 1;
}

sub syslog_close {
    if ($_syslog_inited) {
        Sys::Syslog::closelog();
        $_syslog_inited = 0;
    }
    return;
}

END {
    syslog_close();
}

sub syslog_formatted {
    # do NOT use warn_syslog in this func, or we would loop. warn() is fine.
    my %params    = @_;
    my $criticity = $params{'criticity'} || 'info';
    my $type      = $params{'type'} || 'unknown';
    my $fieldsref = $params{'fields'};

    if (ref $fieldsref ne 'ARRAY') {
        my $error = "bad call to syslog_formatted, invalid fields parameter";
        warn($error);    # this will in turn log into syslog with the trace() thanks to the SIG{'WARN'} handler
        return R('INTERNAL_ERROR', msg => $error);
    }

    my @fields = @$fieldsref;

    unshift @fields, ['gid', ((split(/ /, $)))[0])];
    unshift @fields, ['uid',       $>];
    unshift @fields, ['sudo_user', $ENV{'SUDO_USER'}];
    unshift @fields, ['sysuser',   OVH::Bastion::get_user_from_env()->value];
    unshift @fields, ['ppid',      getppid()];
    unshift @fields, ['pid',       $$];
    unshift @fields, ['version',   $OVH::Bastion::VERSION];
    unshift @fields, ['uniqid', ($ENV{'UNIQID'} || '-')];

    my @msg = ($type);
    if (($type eq 'die' || $type eq 'warn') && $criticity eq 'info') {

        # in that case, "downgrade" the criticity of the message
        @msg = ("$type-$criticity");
    }

    my %dedupe;
    foreach my $item (@fields) {

        # each $item item is a 2-dimensional array for key => value
        if (ref $item ne 'ARRAY') {
            my $error = "bad call to syslog_formatted, invalid item in fields (ref " . (ref $item) . ")";
            warn($error);
            return R('INTERNAL_ERROR', msg => $error);
        }
        my ($key, $value) = @$item;

        # warn if we have the same key more than once
        if (exists $dedupe{$key}) {
            warn("syslog_formatted(): got multiple '$key' keys");
        }
        $dedupe{$key} = $value;

        # remove any \n in the value
        $value =~ s/\n/ /g;

        # replace any \ by an escaped \ aka \\
        $value =~ s{\\}{\\\\}g;

        # replace any " by \"
        $value =~ s{"}{\\"}g;
        push @msg, qq{$key="$value"};
    }

    my $flatmsg = join(" ", @msg);
    OVH::Bastion::syslog($criticity, $flatmsg);
    return R('OK', value => $flatmsg);
}

sub warn_syslog {
    my $msg   = shift;
    my $noisy = shift;
    osh_warn("WARN: " . $msg) if $noisy;
    return syslog_formatted(
        type   => 'code-warning',
        fields => [['msg' => $msg]]
    );
}

sub info_syslog {
    my $msg = shift;
    return syslog_formatted(
        type   => 'code-info',
        fields => [['msg' => $msg]]
    );
}

sub _sql_update_db {
    my %params  = @_;
    my $sqltype = $params{'sqltype'};
    my $dbh     = $params{'dbh'};
    my $sth;
    my $result;
    my $fnret;

    $dbh->do("PRAGMA synchronous=0");

    # get current user_version of db
    $sth = $dbh->prepare("PRAGMA user_version");
    return R('KO', msg => "getting user_version (prepare)") if not $sth;

    $result = $sth->execute();
    return R('KO', msg => "getting user_version (execute)") if not $result;

    my $user_version = $sth->fetchrow_array();

    if ($user_version <= 0) {

        # set journal_mode, this is a no-op if already in WAL
        if (!$dbh->do("PRAGMA journal_mode=WAL")) {
            return R('KO', msg => "setting journal mode");
        }

        # create table
        $result = $dbh->do(
            $sqltype eq 'local'
            ? <<'EOS'
            CREATE TABLE IF NOT EXISTS connections(
                id        INTEGER PRIMARY KEY,
                timestamp INTEGER,
                timestampusec INTEGER,
                account   TEXT,
                cmdtype   TEXT,
                allowed   INTEGER,
                hostfrom  TEXT,
                ipfrom    TEXT,
                portfrom  INTEGER,
                bastionip TEXT,
                bastionport INTEGER,
                hostto    TEXT,
                ipto      TEXT,
                portto    INTEGER,
                user      TEXT,
                plugin    TEXT,
                ttyrecfile TEXT,
                ttyrecsize INTEGER,
                params    TEXT,
                timestampend INTEGER,
                timestampendusec INTEGER,
                returnvalue  INTEGER,
                comment TEXT,
                uniqid  TEXT)
EOS
            : <<'EOS'
            CREATE TABLE IF NOT EXISTS connections_summary(
                    id        INTEGER PRIMARY KEY,
                    timestamp INTEGER,
                    account   TEXT,
                    cmdtype   TEXT,
                    allowed   INTEGER,
                    ipfrom    TEXT,
                    ipto      TEXT,
                    portto    INTEGER,
                    user      TEXT,
                    plugin    TEXT,
                    uniqid    TEXT)
EOS
        );
        return R('KO', msg => "creating table ($sqltype)") if not $result;

        # create indexes if needed
        my @columns = (
            $sqltype eq 'local'
            ? qw{ timestamp ipto uniqid }
            : qw{ timestamp ipto uniqid }
        );
        my $table = ($sqltype eq 'local' ? "connections" : "connections_summary");
        foreach my $column (@columns) {
            $dbh->do("CREATE INDEX IF NOT EXISTS idx_$column ON $table ($column)")
              or return R('KO', msg => "creating index idx_$column on $table");
        }

        $dbh->do("PRAGMA user_version=1")
          or return R('KO', msg => "setting user_version to 1");
        $user_version = 1;
    }

    # endof version==0

    if ($user_version == 1) {
        ;    # insert here future schema modifications
    }

    return R('OK', msg => "sql update done");
}

# don't call me directly, use sql_log_insert() !
sub _sql_log_insert_file {
    my %p = @_;
    my $fnret = OVH::Bastion::check_args(\%p,
        mandatory => [qw{ file account cmdtype timestamp timestampusec uniqid sqltype }],
        mandatoryFalseOk => [qw{ allowed hostfrom ipfrom portfrom bastionip bastionport
            hostto ipto portto user }],
        optionalFalseOk => [qw{ plugin params comment ttyrecfile }],
    );
    $fnret or return $fnret;

    if ($p{'sqltype'} ne 'local' and $p{'sqltype'} ne 'global') {
        return R('ERR_INVALID_PARAMETER', msg => "Invalid parameter sqltype");
    }

    if ($p{'sqltype'} eq 'global') {
        # if it doesn't exist yet, create the file ourselves, chgrp it to bastion-users and set the
        # proper rights (0660). if the file already exists, we won't do anything.
        # -journal -shm and -wal files are created with same perms by sqlite
        OVH::Bastion::create_file_if_not_exists(file => $p{'file'}, perms => oct(660), group => "bastion-users");
    }

    # big db-related retry block:
    # open db, set journal_mode, create table if not exists, insert data
    # opendb usually always works
    # journal_mode can get you a weird transient error on high concurrency (such as "failed to open database")
    # same for create and insert (such as "attempted to write on readonly database")
    # ... so we'll retry up to 20 times if any error arises, starting from the beginning,
    # to ensure we're not locked with a readonly-$dbh for some obscure race-condition-related reason
    my ($dbh, $sth, $result, $doing);
    foreach my $retry (0 .. 19) {

        # if we're retrying, sleep a bit before, to ease concurrency
        sleep($retry / 50 + rand() / 10) if $retry;

        # on each retry, clean those vars (undef $dbh disconnects if connected)
        undef $dbh;
        undef $sth;
        undef $result;
        undef $doing;

        # connect to db
        $dbh = DBI->connect("dbi:SQLite:dbname=".$p{'file'}, "", "", {PrintError => 0, RaiseError => 0});
        if (!$dbh) {
            $doing = "opening database (write)";
            next;    # retry
        }

        my $fnret = _sql_update_db(dbh => $dbh, sqltype => $p{'sqltype'});
        if (!$fnret) {
            $doing = $fnret->msg;
            next;    # retry
        }

        # preparing data insertion query
        my $prepare;
        my @execute;
        if ($p{'sqltype'} eq 'local') {
            @execute = (
                $p{'uniqid'}, $p{'timestamp'}, $p{'timestampusec'}, $p{'account'},     $p{'cmdtype'}, $p{'allowed'}, $p{'hostfrom'},
                $p{'ipfrom'}, $p{'portfrom'},  $p{'bastionip'},     $p{'bastionport'}, $p{'hostto'},  $p{'ipto'},    $p{'portto'},
                $p{'user'},   $p{'plugin'},    $p{'params'},        $p{'comment'},     $p{'ttyrecfile'}
            );
            $prepare =
                "INSERT INTO connections ("
              . "uniqid, timestamp,  timestampusec,  account,       cmdtype,  allowed,  hostfrom,"
              . "ipfrom, portfrom,   bastionip,      bastionport,   hostto,   ipto,     portto,"
              . "user,   plugin,     params,         comment,       ttyrecfile"
              . ') VALUES ('. ('?,' x (@execute - 1)) . '?)';
        }
        elsif ($p{'sqltype'} eq 'global') {
            @execute = ($p{'uniqid'}, $p{'timestamp'}, $p{'account'}, $p{'cmdtype'}, $p{'allowed'},
                $p{'ipfrom'}, $p{'ipto'}, $p{'portto'}, $p{'user'}, $p{'plugin'});
            $prepare =
              "INSERT INTO connections_summary (uniqid,timestamp,account,cmdtype,allowed,ipfrom,ipto,portto,user,plugin)"
              . 'VALUES ('
              . ('?,' x (@execute - 1)) . '?)';
        }

        # prepare insertion on db
        $sth = $dbh->prepare($prepare);
        if (!$sth) {
            $doing = "inserting data (prepare)";
            next;    # retry
        }

        # execute insertion
        $result = $sth->execute(@execute);
        if (!$result) {
            $doing = "inserting data (execute)";
            next;    # retry
        }

        # if we're here, it worked, stop retrying
        last;
    }

    # if this is set, we probably reached max retry in previous loop without succeeding
    if ($DBI::err) {
        my $exists   = -f $p{'file'} ? "exists" : "doesn't exist";
        my $readable = -r $p{'file'} ? "readable" : "non-readable";
        my $writable = -w $p{'file'} ? "writable" : "non-writable";
        warn_syslog("Failed after multiple retries [".$p{'sqltype'}."] err $DBI::err "
            . "while doing [$doing]: $DBI::errstr (".$p{'file'}.", $exists, $readable, $writable)");
        return R('ERR_SQL_EXECUTE', msg => "SQL error [".$p{'sqltype'}."] while doing [$doing]: $DBI::errstr");
    }

    return R('OK', value => {id => $dbh->last_insert_id("", "", "", "")});
}

sub log_access_insert {
    my %p = @_;
    $p{'uniqid'} ||= $ENV{'UNIQID'};
    my $fnret = OVH::Bastion::check_args(\%p,
        mandatory => [qw{ Account }],
        optional => [qw{ uniqid loghome custom }],
        # stuff passed down to _sql_log_insert_file:
        optionalFalseOk => [qw{
            cmdtype bastionip bastionport params ipfrom ipto hostfrom
            portto comment user allowed plugin hostto portfrom
            ttyrecfile
        }],
    );
    $fnret or return $fnret;

    my $Account = delete $p{'Account'};
    # 'loghome' is only used for proxyhttp
    my $custom  = $p{'custom'};                     # only used for proxyhttp, not pushed to sql
    my $fnret;

    # if we get a valid account, we'll try to log to its files, if enabled.
    # if not, or if its invalid, still try to log what we can (hence don't return here)
    # Account can be a normal account or a realm account, in case osh.pl is erroring early and couldn't
    # rresolve the proper remote account (realm/user format)

    my $loghome = delete $p{'loghome'} || $Account->sysUser;
    $p{'account'} = $Account->name;

    if (not defined $p{'hostto'} and defined $p{'ipto'}) {
        $p{'hostto'} = OVH::Bastion::ip2host($p{'ipto'})->value;
    }
    if (not defined $p{'hostfrom'} and defined $p{'ipfrom'}) {
        $p{'hostfrom'} = OVH::Bastion::ip2host($p{'ipfrom'})->value;
    }

    my ($timestamp, $timestampusec) = Time::HiRes::gettimeofday();
    $p{'timestamp'}     = $timestamp;
    $p{'timestampusec'} = $timestampusec;

    # 1/3) log into sql databases if enabled
    my @localtime = localtime(time());
    my ($insert_id, $db_name);

    # first, log in account db
    my $accountsql = 'no';
    if (OVH::Bastion::config('enableAccountSqlLog')->value()) {
        if (-d "/home/$loghome") {
            my $sqlfile = sprintf(
                "/home/%s/%s-log-%04d%02d.sqlite",
                $loghome,
                $loghome || $Account->remoteName,
                $localtime[5] + 1900,
                $localtime[4] + 1
            );
            $fnret = _sql_log_insert_file(
                %p,
                sqltype => "local",
                file    => $sqlfile
            );
            if ($fnret) {
                ($insert_id, $db_name) = ($fnret->value->{'id'}, $sqlfile);
                $accountsql = 'ok';
            }
            else {
                $accountsql = 'error ' . $fnret->msg;
            }
        }
        else {
            warn_syslog("Attempted to log to ${Account}'s sqlite db without a valid loghome ($loghome)");
        }
    }

    # then global db
    my $globalsql = 'no';
    if (OVH::Bastion::config('enableGlobalSqlLog')->value()) {
        $fnret = _sql_log_insert_file(
            %p,
            sqltype => "global",
            file    => sprintf("/home/logkeeper/global-log-%04d%02d.sqlite", $localtime[5] + 1900, $localtime[4] + 1)
        );
        $globalsql = $fnret ? 'ok' : 'error ' . $fnret->msg;
    }

    # 2/3) push to syslog, we'll also say if any sqlinsert failed through globalsql/accountsql
    # even if syslog is disabled, syslog_formatted() will return a oneline $msg that we'll use afterwards
    my @fields = (
        ['account', ($Account?$Account->name:'')],
        ['cmdtype', $p{'cmdtype'}],
        ['allowed', ($p{'allowed'} ? 'true' : 'false')],
        ['ip_from',      $p{'ipfrom'}],
        ['port_from',    $p{'portfrom'}],
        ['host_from',    $p{'hostfrom'}],
        ['ip_bastion',   $p{'bastionip'}],
        ['port_bastion', $p{'bastionport'}],
        ['user',         $p{'user'}],
        ['ip_to',        $p{'ipto'}],
        ['port_to',      $p{'portto'}],
        ['host_to',      $p{'hostto'}],
        ['plugin',       $p{'plugin'}],
        ['globalsql',    $globalsql],
        ['accountsql',   $accountsql],
        ['comment',      $p{'comment'}],
        ['p',       $p{'p'}],
    );
    if (ref $custom eq 'ARRAY') {
        foreach my $item (@$custom) {
            push @fields, $item if (ref $item eq 'ARRAY' && @$item == 2);
        }
    }

    $fnret = syslog_formatted(
        criticity => 'info',
        type      => 'open',
        fields    => \@fields,
    );

    # if syslog_formatted failed, we'll log its error message (->msg)
    # instead of the message it couldn't assemble (->value)
    my $msg = $fnret ? $fnret->value : $fnret->msg;

    # 3/3) push to our own local / global text logs, if enabled, using the $msg returned by syslog_formatted
    _write_log(Account => $Account, msg => $msg);

    # save this for log_access_update()
    my $cache = {
        fields        => \@fields,
        timestamp     => $p{'timestamp'},
        timestampusec => $p{'timestampusec'},
    };
    $ENV{'LOG_CACHE_' . $p{'uniqid'}} = encode_json($cache);

    return R('OK', value => {insert_id => $insert_id, db_name => $db_name, uniq_id => $p{'uniqid'}});
}

sub _sql_log_update_file {
    my %params           = @_;
    my $file             = $params{'file'};
    my $id               = $params{'id'};
    my $returnvalue      = $params{'returnvalue'};
    my $comment          = $params{'comment'};
    my $timestampend     = $params{'timestampend'};
    my $timestampendusec = $params{'timestampendusec'};

    my $plugin_stdout = $params{'plugin_stdout'};
    my $plugin_stderr = $params{'plugin_stderr'};

    if (not $file or not defined $id) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing required parameter file or id");
    }
    if (!-w $file) {
        return R('ERR_FILE_NOT_FOUND', msg => "File $file should already exist");
    }

    my ($dbh, $sth, $result, $doing);

    # retry block
    foreach my $retry (0 .. 19) {

        # if we're retrying, sleep a bit before, to ease concurrency
        sleep($retry / 50 + rand() / 10) if $retry;

        # on each retry, clean those vars (undef $dbh disconnects if connected)
        undef $dbh;
        undef $sth;
        undef $result;
        undef $doing;

        # connect to db
        $dbh = DBI->connect("dbi:SQLite:dbname=$file", "", "", {PrintError => 0, RaiseError => 0});
        if (!$dbh) {
            $doing = "opening database (write)";
            next;    # retry
        }

        my $prepare = "UPDATE connections SET timestampend=?, timestampendusec=?, returnvalue=?";
        my @execute = ($timestampend, $timestampendusec, $returnvalue);

        if (defined $comment) {
            $prepare .= ", comment=?";
            push @execute, $comment;
        }
        $prepare .= " WHERE id=? AND timestampend IS NULL";
        push @execute, $id;

        # prepare insertion on db
        $sth = $dbh->prepare($prepare);
        if (!$sth) {
            $doing = "updating data (prepare)";
            next;    # retry
        }

        # execute insertion
        $result = $sth->execute(@execute);
        if (!$result) {
            $doing = "updating data (execute)";
            next;    # retry
        }

        # if we're here, it worked, stop retrying
        last;
    }

    # if this is set, we probably reached max retry in previous loop without succeeding
    if ($DBI::err) {
        my $exists   = -f $file ? "exists" : "doesn't exist";
        my $readable = -r $file ? "readable" : "non-readable";
        my $writable = -w $file ? "writable" : "non-writable";
        warn_syslog("Failed after multiple retries [updating] err $DBI::err "
            . "while doing [$doing]: $DBI::errstr ($file, $exists, $readable, $writable)");
        return R('ERR_SQL_EXECUTE', msg => "SQL error [updating] while doing [$doing]: $DBI::errstr");
    }

    # if we have plugin stdout or stderr, log it too
    if (defined $plugin_stdout or defined $plugin_stderr) {

        # retry block
        foreach my $retry (0 .. 19) {

            # if we're retrying, sleep a bit before, to ease concurrency
            sleep($retry / 50 + rand() / 10) if $retry;

            # on each retry, clean those vars (undef $dbh disconnects if connected)
            undef $dbh;
            undef $sth;
            undef $result;
            undef $doing;

            # connect to db
            $dbh = DBI->connect("dbi:SQLite:dbname=$file", "", "", {PrintError => 0, RaiseError => 0});
            if (!$dbh) {
                $doing = "opening database (write)";
                next;    # retry
            }

            $sth = $dbh->prepare(
                <<'EOS'
                CREATE TABLE IF NOT EXISTS plugincalls(
                   id        INTEGER PRIMARY KEY,
                   connection_id INTEGER UNIQUE,
                   stdout    TEXT,
                   stderr    TEXT)
EOS
            );
            if (!$sth) {
                $doing = "creating plugins table (prepare)";
                next;    # retry
            }
            $result = $sth->execute();
            if (!$result) {
                $doing = "creating plugins table (execute)";
                next;    # retry
            }

            $sth = $dbh->prepare("INSERT INTO plugincalls (connection_id, stdout, stderr) VALUES (?,?,?)");
            if (!$sth) {
                $doing = "inserting plugincall data (prepare)";
                next;    # retry
            }
            $result = $sth->execute($id, join("\n", @{$plugin_stdout || []}), join("\n", @{$plugin_stderr || []}));
            if (!$result) {
                $doing = "inserting plugincall data (execute)";
                next;    # retry
            }

            # if we're here, it worked, stop retrying
            last;
        }

        # if this is set, we probably reached max retry in previous loop without succeeding
        if ($DBI::err) {
            my $exists   = -f $file ? "exists" : "doesn't exist";
            my $readable = -r $file ? "readable" : "non-readable";
            my $writable = -w $file ? "writable" : "non-writable";
            warn_syslog("Failed after multiple retries [plugins] err $DBI::err "
                . "while doing [$doing]: $DBI::errstr ($file, $exists, $readable, $writable)");
            return R('ERR_SQL_EXECUTE', msg => "SQL error [plugins] while doing [$doing]: $DBI::errstr");
        }
    }

    return R('OK');
}

# called by log_access_insert and log_access_update
# don't re-check the validity of our params, this has been done by our callers
sub _write_log {
    my %params    = @_;
    my @localtime = localtime(time());
    my @date      = ($localtime[5] + 1900, $localtime[4] + 1);

    my $Account = $params{'Account'};
    if ($Account && OVH::Bastion::config('enableAccountAccessLog')->value) {
        my $file = sprintf("%s/%s-log-%04d%02d.log", $Account->home, $Account->remoteName || $Account->sysUser, @date);
        if (open(my $log_acc, ">>", $file)) {
            print $log_acc localtime() . " " . $params{'msg'} . "\n";
            close($log_acc);
        }
    }
    if (OVH::Bastion::config('enableGlobalAccessLog')->value) {
        my $file = sprintf("/home/logkeeper/global-log-%04d%02d.log", @date);
        # if it doesn't exist yet, create the file ourselves, chgrp it to bastion-users and set the
        # proper rights (0660). if the file already exists, we won't do anything.
        OVH::Bastion::create_file_if_not_exists(file => $file, perms => oct(660), group => "bastion-users");
        if (open(my $log_gen, ">>", $file)) {
            print $log_gen localtime() . " " . $params{'msg'} . "\n";
            close($log_gen);
        }
    }
    return;
}

sub log_access_update {
    my %params    = @_;
    my $account   = $params{'account'};
    my $insert_id = $params{'insert_id'};
    my $db_name   = $params{'db_name'};
    my $uniq_id   = $params{'uniq_id'};
    state $update_done;
    my $fnret;

    # ensure we never get called more than once in a process
    return R('OK_DUPLICATE') if $update_done;
    $update_done = 1;

    # if we get a valid account, we'll try to log to its files, if enabled.
    # if not, or if its invalid, still try to log what we can (hence don't return here)
    my $Account;
    if ($account) {
        $Account = OVH::Bastion::Account->newFromName($account);
        if (!$Account->check()) {
            warn_syslog("Got an invalid account '$account'");
            undef $Account;
        }
    }

    if (not defined $params{'timestampend'} or not defined $params{'timestampendusec'}) {
        ($params{'timestampend'}, $params{'timestampendusec'}) = Time::HiRes::gettimeofday();
    }

    # retrieve info from the corresponding "open" log so that we can include it to our log
    my @comments = $params{'comment'} ? split(" ", $params{'comment'}) : ();
    my @fields;
    my $duration = -1;
    if (exists $ENV{'LOG_CACHE_' . $params{'uniq_id'}}) {
        my $cache;
        eval { $cache = decode_json(delete $ENV{'LOG_CACHE_' . $params{'uniq_id'}}); };
        if ($cache) {
            @fields   = @{$cache->{'fields'}};
            $duration = ($params{'timestampend'} + $params{'timestampendusec'} / 1_000_000) -
              ($cache->{'timestamp'} + $cache->{'timestampusec'} / 1_000_000);
        }
    }
    if (!@fields) {
        push @comments, "missing_open_log_info";
    }

    my $signal = '';
    my $status = '';
    if (defined $params{'returnvalue'}) {
        $fnret = OVH::Bastion::sysret2human($params{'returnvalue'});
        if ($fnret && $fnret->value) {
            $signal = $fnret->value->{'signal'};
            $status = $fnret->value->{'status'};
        }
    }
    else {
        # sql logs expect a returnvalue, so set one if we don't have any
        $params{'returnvalue'} = -1;
    }

    # if an explicit signal value has been passed, use it
    if ($params{'signal'}) {
        $signal = delete $params{'signal'};
    }

    push @fields, ['sysret', $status], ['signal', $signal], ['comment_close', join(" ", @comments)],
      ['duration', sprintf("%.3f", $duration)];

    # 1/3) update the account sql db if enabled. note that the global sql db is NOT updated, as
    # it contains less details that the account databases and doesn't have any field that requires
    # to wait the end of a connection to be filled.
    my $accountsql = 'no';
    if (OVH::Bastion::config('enableAccountSqlLog')->value) {
        if ($insert_id && $db_name) {
            $fnret      = _sql_log_update_file(%params, file => $db_name, id => $insert_id);
            $accountsql = $fnret ? 'ok' : 'error ' . $fnret->msg;
        }
        else {
            $accountsql = 'missing';
        }
    }

    # 2/3) push to syslog, we'll also say if the sql update failed through accountsql
    # even if syslog is disabled, syslog_formatted() will return a oneline $msg that we'll use afterwards
    push @fields, [accountsql_close => $accountsql];
    $fnret = syslog_formatted(
        criticity => 'info',
        type      => 'close',
        fields    => \@fields,
    );

    # if syslog_formatted failed, we'll log its error message (->msg) instead of the message it couldn't assemble (->value)
    my $msg = $fnret ? $fnret->value : $fnret->msg;

    # 3/3) push to our own local / global text logs, if enabled, using the $msg returned by syslog_formatted
    _write_log(Account => $Account, msg => $msg);

    return R('OK');
}

sub log_access_get {
    my %p = @_;
    my $fnret = OVH::Bastion::check_args(\%p,
        mandatory => [qw{ Account }],
        # stuff passed down to _sql_log_fetch_from_file
        optionalFalseOk => [qw{ uniqid cmdtype after before allowed ipfrom ipto
            portto bastionip bastionport toPort user limit plugin
        }],
    );
    $fnret or return $fnret;

    my $Account = $p{'Account'};
    $Account or return $Account;

    $fnret = $Account->check();
    $fnret or return $fnret;

    my ($timestamp, $timestampusec) = Time::HiRes::gettimeofday();
    $p{'timestamp'}     = $timestamp;
    $p{'timestampusec'} = $timestampusec;

    my @localtime = localtime(time());

    # check in account sql file
    if (OVH::Bastion::config('enableAccountSqlLog')->value()) {
        $p{'file'} = sprintf(
            "%s/%s-log-%04d%02d.sqlite",
            $Account->home, $Account->remoteName || $Account->sysUser,
            $localtime[5] + 1900,
            $localtime[4] + 1
        );
        $p{'sqltype'} = 'local';
        $fnret = _sql_log_fetch_from_file(%p);
        return $fnret;
    }

    return R('ERR_DISABLED', msg => "This feature is not available");
}

# don't call me directly, use log_access_get() !
sub _sql_log_fetch_from_file {
    my %p = @_;
    my $fnret = OVH::Bastion::check_args(\%p,
        mandatory => [qw{ file sqltype timestamp timestampusec }],
        optional => [qw{ Account }],
        optionalFalseOk => [qw{ uniqid cmdtype after before allowed ipfrom ipto
            portto bastionip bastionport toPort user limit file plugin
        }],
    );
    $fnret or return $fnret;

    foreach my $param (qw{ limit before after }) {
        if (defined $p{$param} && $p{$param} !~ /^\d+$/) {
            return R('ERR_INVALID_PARAMETER', msg => "Expected a numeric $param");
        }
    }

    my @conditions;
    my @execvalues;
    if ($p{'Account'}) {
        push @conditions, "account = ?";
        push @execvalues, $p{'Account'}->name;
    }
    if ($p{'cmdtype'}) {
        push @conditions, "cmdtype = ?";
        push @execvalues, $p{'cmdtype'};
    }
    if (defined $p{'allowed'}) {
        push @conditions, "allowed = ?";
        push @execvalues, $p{'allowed '} ? 1 : 0;
    }
    if ($p{'uniqid'}) {
        push @conditions, "uniqid = ?";
        push @execvalues, $p{'uniqid'};
    }
    if ($p{'user'}) {
        push @conditions, "user = ?";
        push @execvalues, $p{'user'};
    }
    if ($p{'plugin'}) {
        push @conditions, "plugin = ?";
        push @execvalues, $p{'plugin'};
    }
    if ($p{'ipto'}) {
        push @conditions, "ipto = ?";
        push @execvalues, $p{'ipto'};
    }
    if ($p{'portto'}) {
        push @conditions, "portto = ?";
        push @execvalues, $p{'portto'};
    }
    if ($p{'ipfrom'}) {
        push @conditions, "ipfrom = ?";
        push @execvalues, $p{'ipfrom'};
    }
    if ($p{'bastionip'}) {
        push @conditions, "bastionip = ?";
        push @execvalues, $p{'bastionip'};
    }
    if ($p{'bastionport'}) {
        push @conditions, "bastionport = ?";
        push @execvalues, $p{'bastionport'};
    }
    if ($p{'before'}) {
        push @conditions, "timestamp <= ?";
        push @execvalues, $p{'before'};
    }
    if ($p{'after'}) {
        push @conditions, "timestamp >= ?";
        push @execvalues, $p{'after'};
    }

    my $tablename;
    if ($p{'sqltype'} eq 'local') {
        $tablename = 'connections';
    }
    elsif ($p{'sqltype'} eq 'global') {
        $tablename = 'connections_summary';
    }
    else {
        return R('ERR_INVALID_PARAMETER', msg => "Unknown sqltype");
    }

    my $prepare = "SELECT * FROM $tablename WHERE (" . join(') AND (', @conditions) . ") ORDER BY id DESC";

    if ($p{'limit'}) {
        $prepare .= " LIMIT ?";
        push @execvalues, $p{'limit'};
    }

    my $openflags = {PrintError => 0, RaiseError => 0};
    if ($DBD::SQLite::VERSION ge '1.42') {
        eval { $openflags->{'sqlite_open_flags'} = DBD::SQLite::OPEN_READONLY(); };
    }

    osh_debug("SQL query: <$prepare> with params: ". join(", ", @execvalues));

    # big db-related retry block (see comment on _sql_log_insert_file)
    my ($dbh, $result, $doing);
    foreach my $retry (0 .. 19) {

        # if we're retrying, sleep a bit before, to ease concurrency
        sleep($retry / 50 + rand() / 10) if $retry;

        # on each retry, clean those vars (undef $dbh disconnects if connected)
        undef $dbh;
        undef $result;
        undef $doing;

        # connect to db
        $dbh = DBI->connect("dbi:SQLite:dbname=".$p{'file'}, "", "", $openflags);
        if (!$dbh) {
            $doing = "opening database (read)";
            next;    # retry
        }

        # fetch data
        $result = $dbh->selectall_hashref($prepare, 'id', {}, @execvalues);
        if (!$result) {
            $doing = "querying data";
            next;    # retry
        }

        # if we're here, it worked, stop retrying
        last;
    }

    # if this is set, we probably reached max retry in previous loop without succeeding
    if ($DBI::err) {
        my $exists   = -f $p{'file'} ? "exists" : "doesn't exist";
        my $readable = -r $p{'file'} ? "readable" : "non-readable";
        my $writable = -w $p{'file'} ? "writable" : "non-writable";
        warn_syslog("Failed after multiple retries [".$p{'sqltype'}."] err $DBI::err "
            . "while doing [$doing]: $DBI::errstr (".$p{'file'}.", $exists, $readable, $writable)");
        return R('ERR_SQL_EXECUTE', msg => "SQL error [".$p{'sqltype'}."] while doing [$doing]: $DBI::errstr");
    }

    return R('OK', value => $result);
}

1;
