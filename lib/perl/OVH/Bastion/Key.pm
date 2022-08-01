package OVH::Bastion::Key;
# vim: set filetype=perl ts=4 sw=4 sts=4 et:
use common::sense;

use Hash::Util qw{ lock_hashref_recurse };
use Memoize;
use Scalar::Util qw{ refaddr };
use Digest::MD5;

use OVH::Bastion;
use OVH::Result;

use overload (
    '""' => 'id',
    'eq' => 'equals',
    'ne' => 'notEquals',
);

=cut
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
=cut

sub newFromFile {
    my ($objectType, $file, %p) = @_;

    if (!$file) {
        return R('ERR_MISSING_PARAMETER', msg => "Missing argument 'file'");
    }

    my $line;
    if (open(my $fh, '<', $file)) {
        $line = <$fh>;
        close($fh);
    }
    else {
        return R('ERR_CANNOT_OPEN_FILE', msg => "Couldn't open specified file ($!)");
    }

    delete $p{'line'}; # just in case
    $p{'date'} = (stat($file))[9];
    $p{'publicFile'} = $file;
    return __PACKAGE__->newFromKeyLine($line, %p);
}

sub newFromKeygen {
    my ($this, %p) = @_;
    my $fnret = OVH::Bastion::check_args(\%p,
        mandatory => [qw{ folder prefix algo size way }],
        optional => [qw{ uid gid name }],
        optionalFalseOk => [qw{ passphrase group_readable }],
    );

    # FIXME check for algo & size BEFORE generating the key, we'll need the $way also for this

    my ($folder, $prefix) = ($p{'folder'},$p{'prefix'});
    if (!-d $folder) {
        return R('ERR_DIRECTORY_NOT_FOUND', msg => "Specified directory not found ($folder)");
    }

    if (!-w $folder) {
        return R('ERR_DIRECTORY_NOT_WRITABLE', msg => "Specified directory can't be written to ($folder)");
    }

    if ($prefix =~ /^([A-Za-z0-9_.-]{1,64})$/) {
        $prefix = $1; # untaint
    }
    else {
        return R('ERR_INVALID_PARAMETER', msg => "Specified prefix is invalid ($prefix)");
    }

    if (($p{'uid'} || $p{'gid'}) && $< != 0) {
        return R('ERR_INVALID_PARAMETER', msg => "Can't specify uid or gid when not root");
    }

    $fnret = OVH::Bastion::is_allowed_algo_and_size(algo => $p{'algo'}, size => $p{'size'}, way => 'egress');
    $fnret or return $fnret;

    # Forge key
    $p{'passphrase'} = '' if not $p{'passphrase'};
    $p{'size'}       = '' if $p{'algo'} eq 'ed25519';
    my $name = $p{'name'} || $prefix;
    my $sshKeyName = $folder . '/id_' . $p{'algo'} . $p{'size'} . '_' . $prefix . '.' . time();

    if (-e $sshKeyName) {
        return R('ERR_KEY_ALREADY_EXISTS', msg => "Can't forge key, generated name already exists");
    }

    my $bastionName = OVH::Bastion::config('bastionName')->value;

    my @command = ('ssh-keygen');
    push @command, '-t', $p{'algo'};
    push @command, '-b', $p{'size'} if $p{'size'};
    push @command, '-N', $p{'passphrase'};
    push @command, '-f', $sshKeyName;
    push @command, '-C', sprintf('%s@%s:%s', $name, $bastionName, scalar(time));

    $fnret = OVH::Bastion::execute(cmd => \@command, noisy_stderr => 1);
    $fnret->err eq 'OK'
      or return R('ERR_SSH_KEYGEN_FAILED', msg => "Error while generating group key ($fnret)");

    my %files = (
        $sshKeyName          => ($p{'group_readable'} ? oct(440) : oct(400)),
        $sshKeyName . '.pub' => oct(444),
    );
    while (my ($file, $chmod) = each(%files)) {
        if (not -e $file) {
            return R('ERR_SSH_KEYGEN_FAILED', msg => "Couldn't find generated key ($file)");
        }
        chown $p{'uid'}, -1, $file if $p{'uid'};
        chown -1, $p{'gid'}, $file if $p{'gid'};
        chmod $chmod, $file;
    }

    return __PACKAGE__->newFromFile("$sshKeyName.pub");
}

sub newFromKeyLine {
    my ($objectType, $line, %p) = @_;
    $p{'line'} = $line;
    my $fnret = OVH::Bastion::check_args(\%p,
        mandatory => [qw{ line }],
        optionalFalseOk => [qw{ way check date publicFile fast }],
    );
    $fnret or return $fnret;

    my $way = $p{'way'};
    if (defined $way && none { $way eq $_ } qw{ ingress egress }) {
        return R('ERR_INVALID_PARAMETER', msg => "Expected ingress or egress for argument 'way' in newFromKeyLine");
    }
    $way = ucfirst($way);

    $line =~ s/[\r\n]//g;

    # some little sanity check
    if ($line =~ /PRIVATE KEY/) {
        # n00b check
        return R('KO_PRIVATE_KEY');
    }

    my ($prefix, $typecode, $base64, $comment);
    if (length($line) <= 3000 && $line =~ m{^\s*
                ((\S+)\s+)?
                (ssh-dss|ssh-rsa|ecdsa-sha\d+-nistp\d+|ssh-ed\d+)
                \s+
                ([a-zA-Z0-9/=+]+)
                (\s+(.{1,128})?)?
                \s*$
            }x
        )
    {
        ($prefix, $typecode, $base64, $comment) = ($2, $3, $4, $6);
    }
    else {
        return R('KO_NOT_A_KEY', value => {line => $line});
    }

    # rebuild line (this also untaints it)
    $line = $typecode.' '.$base64;
    $prefix = '' if !defined $prefix;
    $line .= " " . $comment if $comment;
    $line = $prefix . " " . $line if $prefix;

    my @fromList;
    if ($prefix =~ /^from=["']([^ "']+)/) {
        @fromList = split /,/, $1;
    }

    # generate a uniq id f($line)
    my $id = 'id' . substr(Digest::MD5::md5_hex($line), 0, 8);

    my $Key = {
        prefix   => $prefix,
        typecode => $typecode,
        base64   => $base64,
        comment  => $comment,
        id       => $id,
        date     => $p{'date'},

        # only for keys from authorized_keys:
        info     => undef,
        isPiv => undef,

        # only filled if !$fast:
        size => undef,
        fingerprint => undef,
        family => undef, # useful vs typecode?
    };


    if (not $p{'fast'}) {
        # put that in a tempfile for ssh-keygen inspection, except if we have the publicFile already
        my $filename = $p{'publicFile'};
        if (!$filename || ! -r -f $filename) {
            my $fh       = File::Temp->new(UNLINK => 1);
            $filename = $fh->filename;
            print {$fh} $typecode . " " . $base64;
            close($fh);
        }

        # FIXME shall we return on error?

        $fnret = OVH::Bastion::execute(cmd => ['ssh-keygen', '-l', '-f', $filename]);
        if ($fnret->is_err || !$fnret->value || ($fnret->value->{'sysret'} != 0 && $fnret->value->{'sysret'} != 1)) {
            # sysret == 1 means ssh-keygen didn't recognize this key, handled below.
            return R('ERR_SSH_KEYGEN_FAILED',
                msg => "Couldn't read the fingerprint of $filename ($fnret)");
        }
        my $sshkeygen;
        if ($fnret->err eq 'OK') {
            $sshkeygen = $fnret->value->{'stdout'}->[0];
            chomp $sshkeygen;
        }

# 2048 01:c0:37:5e:b4:bf:00:b6:ef:d3:65:a7:5c:60:b1:81  john@doe (RSA)
# 521 af:84:cd:70:34:64:ca:51:b2:17:1a:85:3b:53:2e:52  john@doe (ECDSA)
# 1024 c0:4d:f7:bf:55:1f:95:59:be:7e:50:47:e4:81:c3:6a  john@doe (DSA)
# 256 SHA256:Yggd7VRRbbivxkdVwrdt0HpqKNylMK91nNIU+RxndTI john@doe (ED25519)

        if (defined $sshkeygen && $sshkeygen =~ /^(\d+)\s+(\S+)\s+(.+)\s+\(([A-Z0-9]+)\)$/) {
            my ($size, $fingerprint, $comment2, $family) = ($1, $2, $3, $4);
            $Key->{'size'} = $size + 0;
            $Key->{'fingerprint'} = $fingerprint;
            $Key->{'family'}      = $family;

            # check allowed algos and key size
            my $allowedSshAlgorithms = OVH::Bastion::config("allowed${way}SshAlgorithms");
            my $minimumRsaKeySize    = OVH::Bastion::config("minimum${way}RsaKeySize");
            if ($allowedSshAlgorithms && !grep { lc($family) eq $_ } @{$allowedSshAlgorithms->value}) {
                return R('KO_FORBIDDEN_ALGORITHM');
            }
            if ($minimumRsaKeySize && lc($family) eq 'rsa' && $minimumRsaKeySize->value > $size) {
                return R('KO_KEY_SIZE_TOO_SMALL');
            }
        }
        else {
            return R('KO_NOT_A_KEY');
        }
    }

    bless $Key, 'OVH::Bastion::Key';

    lock_hashref_recurse($Key);

    return $Key;
}


BEGIN {
    no strict "refs";

    # simple getters, they have no corresponding setter, as Account objects are immutable
    foreach my $attr (qw{
            prefix typecode base64 comment id date
            info isPiv fingerprint family size
        }) {
        *$attr = sub {
            my $this = shift;
            return $this->{$attr};
        };
    }

    use strict "refs";
}

# special getter
sub line {
    my $this = shift;

    my $line = $this->typecode.' '.$this->base64;
    $line .= " " . $this->comment if $this->comment;
    $line = $this->prefix . " " . $line if $this->prefix;

    return $line;
}

sub from_list {
    my $this = shift;

    my @fromList;
    if ($this->prefix =~ /^from=["']([^ "']+)/) {
        @fromList = split /,/, $1;
    }

    return \@fromList;
}

sub equals {
    my ($this, $that) = @_;
    return (ref $this eq ref $that && $this->line eq $that->line);
}

sub notEquals {
    my ($this, $that) = @_;
    return !($this eq $that);
}

1;

=cut
sub check {
    # put that in a tempfile for ssh-keygen inspection
    if (not $noexec) {
        my $fh       = File::Temp->new(UNLINK => 1);
        my $filename = $fh->filename;
        print {$fh} $typecode . " " . $base64;
        close($fh);
        $fnret = OVH::Bastion::execute(cmd => ['ssh-keygen', '-l', '-f', $filename]);
        if ($fnret->is_err || !$fnret->value || ($fnret->value->{'sysret'} != 0 && $fnret->value->{'sysret'} != 1)) {

            # sysret == 1 means ssh-keygen didn't recognize this key, handled below.
            return R('ERR_SSH_KEYGEN_FAILED',
                msg => "Couldn't read the fingerprint of $filename (" . $fnret->msg . ")");
        }
        my $sshkeygen;
        if ($fnret->err eq 'OK') {
            $sshkeygen = $fnret->value->{'stdout'}->[0];
            chomp $sshkeygen;
        }

# 2048 01:c0:37:5e:b4:bf:00:b6:ef:d3:65:a7:5c:60:b1:81  john@doe (RSA)
# 521 af:84:cd:70:34:64:ca:51:b2:17:1a:85:3b:53:2e:52  john@doe (ECDSA)
# 1024 c0:4d:f7:bf:55:1f:95:59:be:7e:50:47:e4:81:c3:6a  john@doe (DSA)
# 256 SHA256:Yggd7VRRbbivxkdVwrdt0HpqKNylMK91nNIU+RxndTI john@doe (ED25519)

        if (defined $sshkeygen and $sshkeygen =~ /^(\d+)\s+(\S+)\s+(.+)\s+\(([A-Z0-9]+)\)$/) {
            my ($size, $fingerprint, $comment2, $family) = ($1, $2, $3, $4);
            $return{'size'}        = $size + 0;
            $return{'fingerprint'} = $fingerprint;
            $return{'family'}      = $family;
            my @blacklistfiles = qw{ DSA-1024 DSA-2048 RSA-1024 RSA-2048 RSA-4096 };
            if (grep { "$family-$size" eq $_ } @blacklistfiles) {

                # check for vulnkeys
                my $blfile = '/usr/share/ssh/blacklist.' . $family . '-' . $size;
                if (-r $blfile && open(my $fh_blacklist, '<', $blfile)) {
                    my $shortfp = $fingerprint;
                    $shortfp =~ s/://g;
                    $shortfp =~ s/^.{12}//;

                    #print "looking for shortfingerprint=$shortfp...\n";
                    local $_ = undef;
                    while (<$fh_blacklist>) {
                        /^\Q$shortfp\E$/ or next;
                        close($fh_blacklist);
                        return R('KO_VULNERABLE_KEY', value => \%return);
                    }
                    close($fh_blacklist);
                }
            }

            # check allowed algos and key size
            my $allowedSshAlgorithms = OVH::Bastion::config("allowed${way}SshAlgorithms");
            my $minimumRsaKeySize    = OVH::Bastion::config("minimum${way}RsaKeySize");
            if ($allowedSshAlgorithms && !grep { lc($return{'family'}) eq $_ } @{$allowedSshAlgorithms->value}) {
                return R('KO_FORBIDDEN_ALGORITHM', value => \%return);
            }
            if ($minimumRsaKeySize && lc($return{'family'}) eq 'rsa' && $minimumRsaKeySize->value > $return{'size'}) {
                return R('KO_KEY_SIZE_TOO_SMALL', value => \%return);
            }
            return R('OK', value => \%return);
        }
        else {
            return R('KO_NOT_A_KEY', value => \%return);
        }
    }
    else {
        # noexec is set, caller doesn't want us to call ssh-keygen
        return R('OK', value => \%return);
    }
    return R('ERR_INTERNAL', value => \%return);
}
=cut

sub print {
    my ($this, %p) = @_;
    my $fnret = OVH::Bastion::check_args(\%p,
        optional => [qw{ id }],
        optionalFalseOk => [qw{ nokeyline err }],
    );

    require Term::ANSIColor;

    # if id is passed directly, this is a key from an authkeys file, the id is the line number
    # otherwise, we should have an id within the key, it depends on $key->line, usually this is a key from a .pub file (no line number)
    my $id = $p{'id'} || $this->id;

    if ($this->info) {
        my $info = $this->info;

        # parse data from 'info' and print it nicely
        my ($name) = $info =~ m{NAME="([^"]+)};
        osh_info(Term::ANSIColor::colored("name: " . $name, 'cyan'));

        my ($by)      = $info =~ m{ADDED_BY=(\S+)};
        my ($when)    = $info =~ m{DATETIME=(\S+)};
        my ($version) = $info =~ m{VERSION=(\S+)};
        my ($session) = $info =~ m{UNIQID=(\S+)};
        osh_info(
            Term::ANSIColor::colored(
                sprintf(
                    "info: added by %s at %s in session %s running v%s",
                    $by      || '(?)',
                    $when    || '(?)',
                    $session || '(?)',
                    $version || '(?)'
                ),
                'cyan'
            )
        );
    }

    if ($this->isPiv) {
        osh_info(
            Term::ANSIColor::colored(
                "PIV: "
                  . "TouchPolicy="
                  . $this->pivInfo->{'Yubikey'}{'TouchPolicy'}
                  . " PinPolicy="
                  . $this->pivInfo->{'Yubikey'}{'PinPolicy'}
                  . " SerialNo="
                  . $this->pivInfo->{'Yubikey'}{'SerialNumber'}
                  . " Firmware="
                  . $this->pivInfo->{'Yubikey'}{'FirmwareVersion'},
                'magenta'
            )
        );
    }

    osh_info(
        sprintf(
            "%s%s (%s-%d) [%s]%s",
            Term::ANSIColor::colored('fingerprint: ', 'green'),
            $this->fingerprint || 'INVALID_FINGERPRINT',
            $this->family      || 'INVALID_FAMILY',
            $this->size,
            defined $id ? "ID = $id" : POSIX::strftime("%Y/%m/%d", localtime($this->date)),
            $p{'err'} eq 'OK' ? '' : ' ***<<' . $p{'err'} . '>>***',
        )
    );

    if (!$p{'nokeyline'}) {
        osh_info(Term::ANSIColor::colored('keyline', 'red') . ' follows, please copy the *whole* line:');
        print($this->line. "\n");
    }
    osh_info(' ');
    return;
}

sub TO_JSON {
    my $this = shift;
    my $ret = {
        prefix   => $this->prefix,
        typecode => $this->typecode,
        base64   => $this->base64,
        comment  => $this->comment,
        id       => $this->id,
        date     => $this->date,

        # only filled if !$fast:
        size => $this->size,
        fingerprint => $this->fingerprint,,
        family => $this->family,
    };

    if ($this->info) {
        # only for keys from authorized_keys:
        $ret->{'info'} = $this->info,
        $ret->{'isPiv'} = $this->isPiv,
    };

    return $ret;
}

1;
