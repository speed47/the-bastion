package OVH::Bastion::Key;
use common::sense;

use Memoize;
use Scalar::Util qw{ refaddr };
use Digest::MD5;

use OVH::Bastion;
use OVH::Result;

use overload (
    '""' => 'name',
    'eq' => '_eq',
    'ne' => '_ne',
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

sub newFromKeyLine {
    my ($objectType, $line, %p) = @_;
    $p{'line'} = $line;
    my $fnret = OVH::Bastion::check_args(\%p,
        mandatory => [qw{ line }],
        optionalFalseOk => [qw{ way check date publicFile }],
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
    };

    bless $Key, 'OVH::Bastion::Key';

    lock_hashref_recurse($Key);

    return $Key;
}


BEGIN {
    no strict "refs";

    # simple getters, they have no corresponding setter, as Account objects are immutable
    foreach my $attr (qw{
            prefix typecode base64 comment id date
        }) {
        *$attr = sub {
            my $this = shift;
            return $this->{$attr};
        };
    }

=cut
    # simple getters that make no sense for specific account types, in which case we log a warning
    # when they're called, and return undef
    foreach my $attr (qw{ allowedIpFile allowedPrivateFile }) {
        *$attr = sub {
            my ($this, %p) = shift;
            if (none { $this->type eq $_ } qw{ local remote }) {
                OVH::Bastion::warn_syslog("Attempted to access attribute '$attr' on '$this' "
                    . "which is of type ".$this->type);
                return undef;
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
=cut

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

sub _eq {
    my ($this, $that) = @_;
    return (ref $this eq ref $that && $this->line eq $that->line);
}

sub _ne {
    my ($this, $that) = @_;
    return !($this eq $that);
}

1;

__END__

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

=cut
2048 01:c0:37:5e:b4:bf:00:b6:ef:d3:65:a7:5c:60:b1:81  john@doe (RSA)
521 af:84:cd:70:34:64:ca:51:b2:17:1a:85:3b:53:2e:52  john@doe (ECDSA)
1024 c0:4d:f7:bf:55:1f:95:59:be:7e:50:47:e4:81:c3:6a  john@doe (DSA)
256 SHA256:Yggd7VRRbbivxkdVwrdt0HpqKNylMK91nNIU+RxndTI john@doe (ED25519)
=cut

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

1;
