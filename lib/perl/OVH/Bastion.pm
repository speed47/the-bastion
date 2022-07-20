package OVH::Bastion;

# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use common::sense;
use Fcntl;
use POSIX qw(strftime);
use List::Util qw{ any };

use File::Basename;
use lib dirname(__FILE__) . '/..';
use OVH::Bastion::Account;

our $VERSION = '3.09.00-rc3';

BEGIN {
    # only used by the handler below
    my $_SAVED_ARGV = join('^', @ARGV);

    sub _warn_die_handler {
        my ($type, $msg) = @_;

        # ignore if parsing code (undef) or in eval (1)
        return 1 if (!defined $^S || $^S);

        # ignore this unimportant error (perl race condition?)
        return 1 if (defined $msg and $msg =~ m{^panic: (gen_constant_list|fold_constants) JMPENV_PUSH returned 2});

        # eval{} in a BEGIN{} in Net::DNS, ignore it
        return 1 if (defined $msg and $msg =~ m{^Can't locate Net/});

        my $criticity = ($type eq 'die' ? 'err' : 'warning');

        # Net::Server can be noisy if the client fails to establish the SSL connection,
        # transform those die into info to avoid triggering SIEM alerts
        $criticity = 'info' if (defined $msg and $msg =~ m{^Could not finalize SSL connection with client handle});

        require Carp;
        OVH::Bastion::syslogFormatted(
            criticity => $criticity,
            type      => $type,
            fields    => [['msg', $msg], ['program', $0], ['cmdline', $_SAVED_ARGV], ['trace', Carp::longmess()]]
        );
        return 1;
    }

    $SIG{__WARN__} = sub { _warn_die_handler("warn", @_) };
    $SIG{__DIE__}  = sub { _warn_die_handler("die",  @_) };
}

use JSON;
use Term::ANSIColor;

use File::Basename;    # dirname
use Cwd;               # need to use realpath because we use that to build sudoers for groups
our $BASEPATH = Cwd::realpath(dirname(__FILE__) . '/../../../');    # usually /opt/bastion

# untaint $BASEPATH manually because realpath() tainted it back
($BASEPATH) = $BASEPATH =~ m{(\S+)};

use lib dirname(__FILE__) . '/../';
use OVH::Result;

use parent qw( Exporter );
our @EXPORT =                                                       ## no critic (AutomaticExportation)
  qw( osh_header osh_footer osh_exit osh_debug osh_info osh_warn osh_crit osh_ok warn_syslog info_syslog );

our $AUTOLOAD;

use constant {
    EXIT_OK                          => 0,
    EXIT_PLUGIN_ERROR                => 100,
    EXIT_ACCOUNT_INACTIVE            => 101,
    EXIT_HOST_NOT_FOUND              => 102,
    EXIT_READ_ONLY                   => 103,
    EXIT_UNKNOWN_COMMAND             => 104,
    EXIT_EXEC_FAILED                 => 105,
    EXIT_RESTRICTED_COMMAND          => 106,
    EXIT_ACCESS_DENIED               => 107,
    EXIT_PASSFILE_NOT_FOUND          => 108,
    EXIT_OUT_OF_SPACE                => 109,
    EXIT_CONFIGURATION_FAILURE       => 110,
    EXIT_GETOPTS_FAILED              => 111,
    EXIT_NO_HOST                     => 112,
    EXIT_ACCOUNT_EXPIRED             => 113,
    EXIT_INTERACTIVE_DISABLED        => 114,
    EXIT_CONFLICTING_OPTIONS         => 115,
    EXIT_MOSH_DISABLED               => 116,
    EXIT_GOT_SIGNAL                  => 117,
    EXIT_MAINTENANCE_MODE            => 118,
    EXIT_REALM_INVALID               => 119,
    EXIT_ACCOUNT_INVALID             => 120,
    EXIT_TTL_EXPIRED                 => 121,
    EXIT_MFA_PASSWORD_SETUP_REQUIRED => 122,
    EXIT_MFA_TOTP_SETUP_REQUIRED     => 123,
    EXIT_MFA_ANY_SETUP_REQUIRED      => 124,
    EXIT_MFA_FAILED                  => 125,
    EXIT_TTYREC_CMDLINE_FAILED       => 126,
    EXIT_INVALID_REMOTE_USER         => 127,
    EXIT_INVALID_REMOTE_HOST         => 128,
    EXIT_PIV_REQUIRED                => 129,
    EXIT_GET_HASH_FAILED             => 130,
};

use constant {
    MFA_PASSWORD_REQUIRED_GROUP    => 'mfa-password-reqd',
    MFA_PASSWORD_CONFIGURED_GROUP  => 'mfa-password-configd',
    MFA_PASSWORD_BYPASS_GROUP      => 'mfa-password-bypass',
    MFA_TOTP_REQUIRED_GROUP        => 'mfa-totp-reqd',
    MFA_TOTP_CONFIGURED_GROUP      => 'mfa-totp-configd',
    MFA_TOTP_BYPASS_GROUP          => 'mfa-totp-bypass',
    PAM_AUTH_BYPASS_GROUP          => 'bastion-nopam',
    OSH_PUBKEY_AUTH_OPTIONAL_GROUP => 'osh-pubkey-auth-optional',

    TOTP_GAUTH_FILENAME => '.otp',

    # authorized_keys file, relative to the user's HOME directory.
    # if you change this, also change it in lib/shell/functions.inc
    AK_FILE => '.ssh/authorized_keys2',

    OPT_ACCOUNT_INGRESS_PIV_POLICY => 'ingress_piv_policy',
    OPT_ACCOUNT_INGRESS_PIV_GRACE  => 'ingress_piv_grace',
    OPT_ACCOUNT_ALWAYS_ACTIVE      => 'always_active',
    OPT_ACCOUNT_IDLE_IGNORE        => 'idle_ignore',
    OPT_ACCOUNT_OSH_ONLY           => 'osh_only',

    OPT_ACCOUNT_MAX_INACTIVE_DAYS => {key => 'max_inactive_days', public => 1},

    OPT_GROUP_IDLE_LOCK_TIMEOUT => {key => 'idle_lock_timeout'},
    OPT_GROUP_IDLE_KILL_TIMEOUT => {key => 'idle_kill_timeout'},
};

###########
# FUNCTIONS

# for i in *.inc ; do bz=$(basename $i .inc) ; echo "$bz => "'[qw{ '$(grep ^sub $i | grep -v 'sub _' | awk '{print $2}' | tr "\n" " ")'}],' ; done
my %_autoload_files = (
    allowdeny => [
        qw{ get_personal_account_keys get_group_keys is_access_way_granted get_ip ip2host get_user_groups duration2human print_acls is_access_granted ssh_test_access_way get_acls get_acl_way }
    ],
    allowkeeper => [
        qw{ is_user_in_group is_group_existing is_valid_uid get_next_available_uid is_bastion_account_valid_and_existing is_account_valid is_account_existing access_modify is_valid_group is_valid_group_and_existing add_user_to_group get_group_list get_account_list get_realm_list is_admin is_super_owner is_auditor is_group_aclkeeper is_group_gatekeeper is_group_owner is_group_guest is_group_member get_remote_accounts_from_realm is_valid_ttl build_re_from_wildcards }
    ],
    configuration => [
        qw{ load_configuration_file main_configuration_directory load_configuration config account_config plugin_config group_config json_load }
    ],
    execute     => [qw{ sysret2human execute execute_simple result_from_helper helper_decapsulate helper }],
    interactive => [qw{ interactive }],
    jail        => [qw{ jailify }],
    log         => [
        qw{ syslog syslog_close syslogFormatted warn_syslog info_syslog log_access_insert log_access_update log_access_get }
    ],
    mock => [
        qw{ enable_mocking is_mocking set_mock_data mock_get_account_entry mock_get_account_accesses mock_get_account_personal_accesses mock_get_account_legacy_accesses mock_get_group_accesses mock_get_account_guest_accesses }
    ],
    os => [
        qw{ sysinfo is_linux is_debian is_redhat is_bsd is_freebsd is_openbsd is_netbsd has_acls sys_useradd sys_groupadd sys_userdel sys_groupdel sys_addmembertogroup sys_delmemberfromgroup sys_changepassword sys_neutralizepassword sys_setpasswordpolicy sys_getpasswordinfo sys_getsudoersfolder sys_setfacl is_in_path sys_getpw_all sys_getpw_all_cached sys_getpw_name sys_getgr_all sys_getgr_all_cached sys_getgr_name }
    ],
    password => [qw{ get_hashes_from_password get_password_file get_hashes_list is_valid_hash }],
    ssh      => [
        qw{ has_piv_helper verify_piv get_authorized_keys_from_file add_key_to_authorized_keys_file put_authorized_keys_to_file get_ssh_pub_key_info is_valid_public_key get_from_for_user_key generate_ssh_key get_bastion_ips get_supported_ssh_algorithms_list is_allowed_algo_and_size is_valid_fingerprint print_public_key account_ssh_config_get account_ssh_config_set ssh_ingress_keys_piv_apply is_effective_piv_account_policy_enabled }
    ],
);

sub AUTOLOAD {    ## no critic (AutoLoading)
    my $subname = $AUTOLOAD;
    $subname =~ s/.*:://;

    foreach my $file (keys %_autoload_files) {
        if (grep { $subname eq $_ } @{$_autoload_files{$file}}) {
            require $BASEPATH . '/lib/perl/OVH/Bastion/' . $file . '.inc';

            # Catch a declared but not implemented subroutine before calling it
            if (not exists &$AUTOLOAD) {
                die "AUTOLOAD FAILED: forgot to declare $subname in $file";
            }

            goto &$AUTOLOAD;
        }
    }

    die "AUTOLOAD FAILED: $AUTOLOAD";
}

# Check whether a user is still active, if this feature has been enabled in the config
sub json_output {    ## no critic (ArgUnpacking)
    my $R             = shift;
    my %params        = @_;
    my $force_default = $params{'force_default'};
    my $no_delimiters = $params{'no_delimiters'};
    my $command       = $params{'command'} || $ENV{'PLUGIN_NAME'};

    my $JsonObject = JSON->new->utf8;
    $JsonObject = $JsonObject->convert_blessed(1);
    if ($ENV{'PLUGIN_JSON'} eq 'PRETTY' and not $force_default) {
        $JsonObject->pretty(1);
    }
    my $encoded_json =
      $JsonObject->encode({error_code => $R->err, error_message => $R->msg, command => $command, value => $R->value});

    # rename forbidden strings
    $encoded_json =~ s/JSON_(START|OUTPUT|END)/JSON__$1/g;

    if ($no_delimiters) {
        print $encoded_json;
    }
    elsif ($ENV{'PLUGIN_JSON'} eq 'GREP' and not $force_default) {
        $encoded_json =~ tr/\r\n/ /;
        print "\nJSON_OUTPUT=$encoded_json\n";
    }
    else {
        print "\nJSON_START\n$encoded_json\nJSON_END\n";
    }
    return;
}

sub osh_header {
    my $text = shift || '';

    require Sys::Hostname;
    my $hostname    = Sys::Hostname::hostname();
    my $versionline = 'the-bastion-' . $VERSION;
    my $output      = '';
    my $fanciness   = OVH::Bastion::config('fanciness')->value;
    if (OVH::Bastion::can_use_utf8() && grep { $fanciness eq $_ } qw{ basic full }) {
        my $line =
            "\N{U+256D}\N{U+2500}\N{U+2500}"
          . $hostname
          . "\N{U+2500}" x (80 - length($hostname) - length($versionline) - 6)
          . $versionline
          . "\N{U+2500}" x 3 . "\n";
        $output .= colored($line,                                   'bold blue');
        $output .= colored("\N{U+2502} \N{U+25B6} $text\n",         'blue');
        $output .= colored("\N{U+251C}" . "\N{U+2500}" x 79 . "\n", 'blue');
    }
    else {
        my $line =
            '-' x 3
          . $hostname
          . '-' x (80 - length($hostname) - length($versionline) - 6)
          . $versionline
          . '-' x 3 . "\n";
        $output .= colored($line,           'bold blue');
        $output .= colored("=> $text\n",    'blue');
        $output .= colored('-' x 80 . "\n", 'blue');
    }

    print $output unless ($ENV{'PLUGIN_QUIET'});
    return;
}

sub osh_footer {
    my $text = shift;
    if (not defined $text) {
        $text = $ENV{'PLUGIN_NAME'};
    }

    my $output;
    my $fanciness = OVH::Bastion::config('fanciness')->value;
    if (OVH::Bastion::can_use_utf8() && grep { $fanciness eq $_ } qw{ basic full }) {
        $output = colored("\N{U+2570}" . "\N{U+2500}" x (79 - length($text) - 6) . "</$text>" . "\N{U+2500}" x 3 . "\n",
            'bold blue');
    }
    else {
        $output = colored('-' x (80 - length($text) - 6) . "</$text>---" . "\n", 'bold blue');
    }

    print $output unless ($ENV{'PLUGIN_QUIET'});
    return;
}

# Used to exit plugins. Can be used in several ways:
# With an R object: osh_exit(R('OK', value => {}, msg => "okey"))
# Or with 1 value, that will be taken as the R->err: osh_exit('OK')
# Or with 2 values, that will be taken as err, msg: osh_exit('ERR_UNKNOWN', 'Unexpected error')
# With more values, they'll be used as constructor for an R object
sub osh_exit {    ## no critic (ArgUnpacking)
    my $R;
    if (@_ == 1) {
        $R = ref $_[0] eq 'OVH::Result' ? $_[0] : R($_[0]);
    }
    elsif (@_ == 2) {
        my $err = shift || 'OK';
        my $msg = shift;
        $R = R($err, msg => $msg);
    }
    else {
        $R = R(@_);
    }

    if (!$R && $R->msg) {
        OVH::Bastion::osh_crit($R->msg);
    }
    elsif ($R->msg ne $R->err && $R->msg) {
        OVH::Bastion::osh_info($R->msg);
    }

    if ($ENV{'PLUGIN_JSON'}) {
        OVH::Bastion::json_output($R);
    }
    osh_footer();

    exit($R ? OVH::Bastion::EXIT_OK : OVH::Bastion::EXIT_PLUGIN_ERROR);
}

sub osh_ok {    ## no critic (ArgUnpacking)
    my $R = ref $_[0] eq 'OVH::Result' ? $_[0] : R('OK', value => $_[0], msg => $_[1]);

    if ($R->msg ne $R->err) {
        OVH::Bastion::osh_info($R->msg);
    }

    if ($ENV{'PLUGIN_JSON'}) {
        OVH::Bastion::json_output($R);
    }
    osh_footer();
    exit OVH::Bastion::EXIT_OK;
}

sub osh_debug {
    my $text = shift;
    if (($ENV{'PLUGIN_DEBUG'} or $ENV{'OSH_DEBUG'}) and not $ENV{'PLUGIN_QUIET'}) {
        foreach my $line (split /^/, $text) {
            chomp $line;
            print STDERR colored("~ <$$:$0> $line", 'bold black') . "\n";
        }
    }
    return;
}

sub osh_info {
    my @lines = @_;
    return _osh_log(text => join('', @lines), type => 'info');
}

sub osh_warn {
    my @lines = @_;
    return _osh_log(text => join('', @lines), type => 'warn');
}

sub osh_crit {
    my @lines = @_;
    return _osh_log(text => "\n" . join('', @lines), type => 'crit');
}

sub _osh_log {
    my %params = @_;

    my $output = $ENV{'FORCE_STDERR'} ? *STDERR : *STDOUT;
    if ($ENV{'PLUGIN_QUIET'}) {
        print $output $params{'text'} . "\n";
    }
    else {
        my $prefix =
          OVH::Bastion::can_use_utf8() && OVH::Bastion::config('fanciness')->value eq 'full' ? "\N{U+2502}" : '~';
        my $prefixIfNotEmpty = '';
        my $color;
        if ($params{'type'} eq 'crit') {
            $prefixIfNotEmpty = (OVH::Bastion::can_use_utf8()
                  && OVH::Bastion::config('fanciness')->value eq 'full' ? "\N{U+26D4}" : "[!]");
            $color = 'red bold';
        }
        elsif ($params{'type'} eq 'warn') {
            $prefixIfNotEmpty = (OVH::Bastion::can_use_utf8()
                  && OVH::Bastion::config('fanciness')->value eq 'full' ? "\N{U+2757}" : "[#]");
            $color = 'yellow';
        }
        else {
            $color = 'blue';
        }
        foreach my $line (split /^/, $params{'text'}) {
            chomp $line;
            my $realPrefix = $prefix;
            $realPrefix .= ' ' . $prefixIfNotEmpty if (length($line) && $prefixIfNotEmpty);

            if ($params{'type'} eq 'info') {
                print $output colored("$realPrefix ", $color) . "$line\n";
            }
            else {
                print $output colored("$realPrefix $line", $color) . "\n";
            }
        }
    }
    return;
}

sub is_valid_ip {
    my %params        = @_;
    my $ip            = $params{'ip'};
    my $allowPrefixes = $params{'allowPrefixes'};    # if not, a /24 or /32 notation is rejected
    my $fast          = $params{'fast'};             # fast mode: avoid instantiating Net::IP... except if ipv6

    if ($fast and $ip !~ m{:}) {

        # fast asked and it's not an IPv6, regex ftw
        ## no critic (ProhibitUnusedCapture)
        if (
            $ip =~ m{^(?<shortip>
                (?<x1>[0-9]{1,3})
                \.
                (?<x2>[0-9]{1,3})
                \.
                (?<x3>[0-9]{1,3})
                \.
                (?<x4>[0-9]{1,3})
               )
               (
                (?<slash>/)
                (?<prefix>\d+)
               )?
            $}x
          )
        {
            if (defined $+{'prefix'} and not $allowPrefixes) {
                return R('KO_INVALID_IP', msg => "Invalid IP address ($ip), as prefixes are not allowed");
            }
            foreach my $key (qw{ x1 x2 x3 x4 }) {
                return R('KO_INVALID_IP', msg => "Invalid IP address ($ip)")
                  if (not defined $+{$key} or $+{$key} > 255);
            }
            if (defined $+{'prefix'} and $+{'prefix'} > 32) {
                return R('KO_INVALID_IP', msg => "Invalid IP address ($ip)");
            }
            if (defined $+{'slash'} and not defined $+{'prefix'}) {

                # got a / in $ip but it's not followed by \d+
                return R('KO_INVALID_IP', msg => "Invalid IP address ($ip)");
            }
            return R('OK', value => {ip => $ip}) if (defined $+{'prefix'} && $+{'prefix'} != 32);
            return R('OK', value => {ip => $+{'shortip'}});
        }
        return R('KO_INVALID_IP', msg => "Invalid IP address ($ip)");
    }

    require Net::IP;
    my $IpObject = Net::IP->new($ip);

    if (not $IpObject) {
        return R('KO_INVALID_IP', msg => "Invalid IP address ($ip)");
    }

    my $shortip = $IpObject->prefix;

    # if /32 or /128, omit the /prefixlen on $shortip
    my $type = 'prefix';
    if (   ($IpObject->version == 4 and $IpObject->prefixlen == 32)
        or ($IpObject->version == 6 and $IpObject->prefixlen == 128))
    {
        $shortip =~ s'/\d+$'';
        $type = 'single';
    }

    if (not $allowPrefixes and $type eq 'prefix') {
        return R('KO_INVALID_IP', msg => "Invalid IP address ($ip), as prefixes are not allowed");
    }

    return R(
        'OK',
        value => {
            ip        => $shortip,
            prefix    => $IpObject->prefix,
            prefixlen => $IpObject->prefixlen,
            version   => $IpObject->version,
            type      => $type
        }
    );
}

sub is_valid_port {
    my %params = @_;
    my $port   = $params{'port'};
    if ($port =~ /^(\d+)$/ && $port > 0 && $port <= 65535) {
        return R('OK', value => $1);
    }
    return R('ERR_INVALID_PARAMETER', msg => "Port must be numeric and 0 < port <= 65535");
}

sub is_valid_remote_user {
    my %params = @_;
    my $user   = $params{'user'};
    if ($user =~ /^([a-zA-Z0-9._!-]{1,128})$/) {
        return R('OK', value => $1);
    }
    return R('ERR_INVALID_PARAMETER', msg => "Specified user doesn't seem to be valid");
}

sub touch_file {
    my $file  = shift;
    my $perms = shift;

    my $ret;
    my $fh;
    if (defined $perms) {
        $ret = sysopen($fh, $file, O_RDWR | O_CREAT, $perms);
    }
    else {
        $ret = sysopen($fh, $file, O_RDWR | O_CREAT);
    }

    if ($ret) {
        close($fh);
        utime(undef, undef, $file);    # update mod/access time to now
                                       # just in case we didn't create the file, and $perms is specified, chmod the file
        chmod $perms, $file if $perms;
        return R('OK');
    }

    # else
    warn_syslog(sprintf("Couldn't touch file '%s' with perms %o: %s", $file, $perms, $!));
    return R('KO', msg => "Couldn't create file $file: $!");
}

sub create_file_if_not_exists {
    my %params = @_;
    my $file   = $params{'file'};
    my $perms  = $params{'perms'};    # must be an octal value (not a string)
    my $group  = $params{'group'};

    my $fh;

    # this call will fail if the file already exists
    my $ret = sysopen($fh, $file, O_RDWR | O_CREAT | O_EXCL);

    if ($ret) {
        close($fh);

        # - set the proper group, if specified
        if ($group) {
            my $gid = getgrnam($group);
            if (defined $gid) {
                if (!chown -1, $gid, $file) {
                    warn_syslog("Couldn't chgrp $file to group $group (GID $gid): $!");
                }
            }
            else {
                warn_syslog("Couldn't chgrp $file to group $group (no GID found)");
            }
        }

        # only if we did create the file:
        # - set the proper perms on it, if specified
        if ($perms) {
            if (!chmod($perms, $file)) {
                warn_syslog("Couldn't chmod $file to perms $perms ($!)");
            }
        }

        # done
        return R('OK');
    }

    # else
    return R('KO', msg => "Couldn't create file $file: $!");
}

sub get_plugin_list {
    my %params         = @_;
    my $restrictedOnly = $params{'restrictedOnly'};

    my %plugins;
    foreach my $dir (
        $OVH::Bastion::BASEPATH . '/bin/plugin/open',
        $OVH::Bastion::BASEPATH . '/bin/plugin/group-gatekeeper',
        $OVH::Bastion::BASEPATH . '/bin/plugin/group-aclkeeper',
        $OVH::Bastion::BASEPATH . '/bin/plugin/group-owner',
        $OVH::Bastion::BASEPATH . '/bin/plugin/restricted',
        $OVH::Bastion::BASEPATH . '/bin/plugin/admin',
      )
    {
        if (opendir(my $dh, $dir)) {
            while (my $file = readdir($dh)) {

                # if exists, will be overwritten, that's why the order of foreach(dir) is important,
                # from most open to most restricted (but plugins should never have the same name anyway)
                $plugins{$file} = {name => $file, dir => $dir} if ($file !~ /\./);
            }
            close($dh);
        }
    }
    if ($restrictedOnly) {
        foreach my $plugin (keys %plugins) {
            delete $plugins{$plugin} if $plugins{$plugin}->{'dir'} !~ m{/restricted$};
        }
    }
    return R('OK', value => \%plugins);
}

sub is_plugin_readonly_proof {
    my %params = @_;
    my $plugin = $params{'plugin'};
    if (not defined $plugin) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing parameter 'plugin'");
    }
    my $fnret = OVH::Bastion::plugin_config(plugin => $plugin, key => "master_only");
    if ($fnret && $fnret->value) {
        return R('KO_NOT_READONLY', msg => "Plugin not allowed in readonly mode");
    }

    # if not "1" or not defined, default to allow on master or slaves
    return R('OK');
}

sub set_terminal_mode_for_plugin {
    my %params = @_;
    my $plugin = $params{'plugin'};
    my $action = $params{'action'};

    if (my @missingParameters = grep { not defined $params{$_} } qw{ plugin action }) {
        local $" = ', ';
        return R('ERR_MISSING_PARAMETER', "Missing mandatory parameter(s): @missingParameters");
    }
    if (not grep { $action eq $_ } qw{ set restore }) {
        return R('ERR_INVALID_PARAMETER', "Parameter 'action' is invalid, expected either 'set' or 'restore'");
    }

    my $mode;
    my $fnret = OVH::Bastion::plugin_config(plugin => $plugin, key => "terminal_mode");
    if ($fnret && defined $fnret->value) {
        if (grep { $fnret->value eq $_ } qw{ noecho cbreak raw }) {
            $mode = $fnret->value;
        }
        else {
            osh_warn("Invalid terminal configuration setup for plugin $plugin, please report to your sysadmin!");
        }
    }

    # noecho: user might type passwords there
    # cbreak: only allow CTRL+C
    # raw: block CTRL+C

    return R('OK_NOT_NEEDED') if not defined $mode;

    $mode = 'restore' if $action eq 'restore';

    require Term::ReadKey;
    Term::ReadKey::ReadMode($mode);
    return R('OK');    # ReadMode returns nothing :(
}

sub generate_uniq_id {
    require Digest::SHA;
    return R('OK', value => unpack("H12", Digest::SHA::sha512(pack("SLL", $$, time, int(rand(2**32))))));
}

sub get_user_from_env {
    my ($sanitized) = (getpwuid($>))[0] =~ /([0-9a-zA-Z_.-]+)/;
    return R('OK', value => $sanitized);
}

sub get_home_from_env {
    my ($sanitized) = (getpwuid($>))[7] =~ m{^([a-zA-Z0-9_/.-]+)$};
    $sanitized =~ s/\.+/./g; # disallow 2 or more consecutive dots, i.e. "john.doe" is ok, "john/../../../etc/passwd" is not
    return R('OK', value => $sanitized);
}

sub get_passfile {
    my %params    = @_;
    my $nameHint  = $params{'hint'};
    my $context   = $params{'context'};
    my $tryLegacy = $params{'tryLegacy'};
    my $self      = $params{'self'} || OVH::Bastion::get_user_from_env()->value;

    $nameHint =~ s/[^a-zA-Z0-9_.-]//g;

    if ($context eq 'self') {

        # in this case, we look into the $self home dir
        my $home     = OVH::Bastion::get_home_from_env()->value;
        my $passFile = "$home/pass/$self";
        return R('OK', value => $passFile) if (-f -r $passFile);
    }
    elsif ($context eq 'group') {

        # new mode: nameHint is actually the name of a group (technically, shortGroup)
        my $passFile = "/home/key$nameHint/pass/$nameHint";
        return R('OK', value => $passFile) if (-f -r $passFile);

        if ($tryLegacy) {

            # auto fall back to legacy mode: nameHint is a file under the global /home/passkeeper directory
            $passFile = "/home/passkeeper/$nameHint";
            return R('OK', value => $passFile) if (-f -r $passFile);
        }
    }
    elsif ($context eq 'legacy') {

        # legacy mode only: nameHint is a file under the global /home/passkeeper directory
        my $passFile = "/home/passkeeper/$nameHint";
        return R('OK', value => $passFile) if (-f -r $passFile);
    }
    return R('KO_PASSFILE_NOT_FOUND',
        msg => "Unable to find (or read) a password file in context '$context' and name '$nameHint'");
}

sub build_ttyrec_cmdline {
    my %params = @_;
    my $fnret  = build_ttyrec_cmdline_part1of2(%params);
    $fnret or return $fnret;

    # for this simple version, use global timeout values
    return build_ttyrec_cmdline_part2of2(
        input           => $fnret->value,
        idleLockTimeout => OVH::Bastion::config("idleLockTimeout")->value,
        idleKillTimeout => OVH::Bastion::config("idleKillTimeout")->value
    );
}

sub build_ttyrec_cmdline_part1of2 {
    my %params = @_;

    if (!$params{'home'}) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing home parameter");
    }
    if (!$params{'ip'}) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing ip parameter");
    }

    # build ttyrec filename format
    my $bastionName          = OVH::Bastion::config('bastionName')->value;
    my $ttyrecFilenameFormat = OVH::Bastion::config('ttyrecFilenameFormat')->value;
    $ttyrecFilenameFormat =~ s/&bastionname/$bastionName/g;
    $ttyrecFilenameFormat =~ s/&uniqid/$params{'uniqid'}/g if $params{'uniqid'};
    $ttyrecFilenameFormat =~ s/&ip/$params{'ip'}/g if $params{'ip'};
    $ttyrecFilenameFormat =~ s/&port/$params{'port'}/g if $params{'port'};
    $ttyrecFilenameFormat =~ s/&user/$params{'user'}/g if $params{'user'};
    $ttyrecFilenameFormat =~ s/&account/$params{'account'}/g if $params{'account'};

    if ($ttyrecFilenameFormat =~ /&(bastionname|uniqid|ip|port|user|account)/) {

        # if we still have a placeholder here, then we were missing parameters
        return R('ERR_MISSING_PARAMETER',
            msg => "Missing bastionname, uniqid, ip, port, user or account in ttyrec cmdline building");
    }

    # ensure there are no '/'
    $ttyrecFilenameFormat =~ tr{/}{_};

    # preprend (and create) directory
    my $saveDir = $params{'home'} . "/ttyrec";
    mkdir($saveDir);
    if ($params{'realm'} && $params{'remoteaccount'}) {
        $saveDir .= "/" . $params{'remoteaccount'};
        mkdir($saveDir);
    }
    $saveDir .= "/" . $params{'ip'};
    mkdir($saveDir);

    my $saveFileFormat = "$saveDir/$ttyrecFilenameFormat";

    # also build the first ttyrec filename ourselves
    my $saveFile = $saveFileFormat;
    $saveFile = strftime($saveFile, localtime(time));
    if ($saveFile =~ /#usec#/) {
        require Time::HiRes;
        my $usec = sprintf("%06d", (Time::HiRes::gettimeofday())[1]);
        $saveFile =~ s{#usec#}{$usec}g;
    }

    # forge ttyrec command
    my @ttyrec = ('ttyrec', '-f', $saveFile, '-F', $saveFileFormat);
    push @ttyrec, '-v' if $params{'debug'};
    push @ttyrec, '-T', 'always' if $params{'tty'};
    push @ttyrec, '-T', 'never'  if $params{'notty'};

    my $fnret = OVH::Bastion::account_config(
        account => $params{'account'},
        key     => OVH::Bastion::OPT_ACCOUNT_IDLE_IGNORE,
        public  => 1
    );
    if ($fnret && $fnret->value =~ /yes/) {
        osh_debug("Account is immune to idle, not adding ttyrec commandline parameters");
        return R('OK', value => {saveFile => $saveFile, cmd => \@ttyrec, idleIgnore => 1});
    }
    else {
        return R('OK', value => {saveFile => $saveFile, cmd => \@ttyrec, idleIgnore => 0});
    }
}

# call this after build_ttyrec_cmdline_part1of2, don't forget to
# pass part1of2's value output to part2of2's 'input' parameter
sub build_ttyrec_cmdline_part2of2 {
    my %params = @_;

    my $input = $params{'input'};
    if (!$input) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing 'input' parameter in build_ttyrec_cmdline_part2of2");
    }

    if (!$input->{'cmd'}) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing 'input->cmd' parameter in build_ttyrec_cmdline_part2of2");
    }

    my @cmd = @{$input->{'cmd'}};

    # if account is immune to idle, don't add these params to ttyrec cmdline
    if (!$input->{'idleIgnore'}) {
        my $idleLockTimeout = $params{'idleLockTimeout'};
        if ($idleLockTimeout) {
            push @cmd, '-t', $idleLockTimeout;
            push @cmd, '-s', "To unlock, use '--osh unlock' from another console";

            my $warnBeforeLockSeconds = OVH::Bastion::config('warnBeforeLockSeconds')->value;
            push @cmd, '--warn-before-lock', $warnBeforeLockSeconds if $warnBeforeLockSeconds;
        }

        my $idleKillTimeout = $params{'idleKillTimeout'};
        if ($idleKillTimeout) {
            push @cmd, '-k', $idleKillTimeout;

            my $warnBeforeKillSeconds = OVH::Bastion::config('warnBeforeKillSeconds')->value;
            push @cmd, '--warn-before-kill', $warnBeforeKillSeconds if $warnBeforeKillSeconds;
        }
    }

    my $ttyrecAdditionalParameters = OVH::Bastion::config('ttyrecAdditionalParameters')->value;
    push @cmd, @$ttyrecAdditionalParameters if @$ttyrecAdditionalParameters;

    $input->{'cmd'} = \@cmd;
    return R('OK', value => $input);
}

sub do_pamtester {
    my %params = @_;
    my $Self   = $params{'Self'};
    my $fnret;

    if (!$Self) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing mandatory argument 'Self'");
    }

    # if we're being called as part of the batch plugin, OSH_BATCH will be set and it means
    # we can't grab the term, so pam can't set raw mode to avoid local echo, and it could end
    # up having passwords typed by the user displayed on screen. In that case, refuse to do it,
    # and return an error to our caller.
    if ($ENV{'OSH_BATCH'}) {
        return R('KO_MFA_TERM_NOT_RAW',
            msg => "MFA is required for this action, but we're running under batch mode, please use --proactive-mfa");
    }

    # use system() instead of OVH::Bastion::execute() because we need it to grab the term
    my $pamtries = 3;
    while (1) {
        my $pamsysret;
        if (OVH::Bastion::is_freebsd()) {
            $pamsysret = system(
                'sudo',         '-n',        '-u',   'root',         '--',
                '/usr/bin/env', 'pamtester', 'sshd', $Self->sysName, 'authenticate'
            );
        }
        else {
            $pamsysret = system('pamtester', 'sshd', $Self->sysName, 'authenticate');
        }
        if ($pamsysret < 0) {
            return R('KO_MFA_FAILED',
                msg => "MFA is required for this action, but this bastion is missing the `pamtester' tool, aborting");
        }
        elsif ($pamsysret != 0) {
            if (--$pamtries <= 0) {
                return R('KO_MFA_FAILED',
                    msg => "Sorry, but Multi-Factor Authentication failed, couldn't complete the requested action");
            }
            next;
        }

        # success, if we are configured to launch a external command on pamtester success, do it.
        # see the bastion.conf.dist file for usage example.
        my $MFAPostCommand = OVH::Bastion::config('MFAPostCommand')->value;
        if (ref $MFAPostCommand eq 'ARRAY' && @$MFAPostCommand) {
            s/%ACCOUNT%/$Self->name/g for @$MFAPostCommand;    # FIXME should be sysName?
            $fnret = OVH::Bastion::execute(cmd => $MFAPostCommand, must_succeed => 1);
            if (!$fnret) {
                warn_syslog("MFAPostCommand returned a non-zero value: " . $fnret->msg);
            }
        }
        last;
    }
    return R('OK_MFA_SUCCESS');
}

sub can_use_utf8 {

    # only use UTF-8 if user LANG seems to support it, and if TERM is defined and not dumb
    return ($ENV{'LANG'} && ($ENV{'LANG'} =~ /utf-?8/i) && $ENV{'TERM'} && $ENV{'TERM'} !~ /dumb|unknown/i);
}

sub check_args {
    my ($args, %p) = @_;
    my $mandatory        = $p{'mandatory'}        || [];
    my $mandatoryFalseOk = $p{'mandatoryFalseOk'} || [];
    my $optional         = $p{'optional'}         || [];
    my $optionalFalseOk  = $p{'optionalFalseOk'}  || [];
    my $unknownOk        = $p{'unknownOk'};

    # if this hash is not empty at the end of this func, mandatory keys are missing
    my %unseenMandatory = map { $_ => 1 } (@$mandatory, @$mandatoryFalseOk);

    # if these arrays are not empty at the end of this func, our caller has a problem
    my @errorUnknown;
    my @errorMissing;
    my @errorFalse;

    my $callerStack = (caller(1))[3];
    my $i           = 2;
    while (caller($i)) {
        my $func = (caller($i))[3];
        $callerStack .= " < $func" if $func !~ m{^Memoize};
        $i++;
    }

    foreach my $key (keys %$args) {
        # we've seen this key, drop it from the keys-that-are-yet-to-be-seen
        delete $unseenMandatory{$key};

        if (!$unknownOk && !any { $key eq $_ } (@$optional, @$mandatory, @$optionalFalseOk, @$mandatoryFalseOk)) {
            # this key is unknown, and it's not ok to be unknown
            push @errorUnknown, $key;
        }
        elsif (!$args->{$key} && !any { $key eq $_ } (@$mandatoryFalseOk, @$optionalFalseOk)) {
            # this key exists but its value is false (empty/undef/0), and it's not ok to be false
            push @errorFalse, $key;
        }
    }

    # all the unseen keys are problematic at this stage
    push @errorMissing, keys %unseenMandatory;

    # log verbose info in logs
    osh_warn(
        sprintf("check_args: mandatory parameters '@errorMissing' missing in call to '%s' by '%s'", $callerStack, $0))
      if @errorMissing;
    osh_warn(sprintf("check_args: unknown parameters '@errorUnknown' in func '%s' by '%s'", $callerStack, $0))
      if @errorUnknown;
    osh_warn(sprintf("check_args: false value for parameters '@errorFalse' in func '%s' by '%s'", $callerStack, $0))
      if @errorFalse;

    return R('ERR_MISSING_ARGUMENT', msg => "Missing arguments: @errorMissing") if @errorMissing;
    return R('ERR_UNKNOWN_ARGUMENT', msg => "Unknown arguments: @errorUnknown") if @errorUnknown;
    return R('ERR_EMPTY_ARGUMENT',   msg => "Empty arguments: @errorFalse")     if @errorFalse;
    return R('OK');
}

1;
