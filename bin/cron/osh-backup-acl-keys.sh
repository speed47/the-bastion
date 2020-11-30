#! /usr/bin/env bash
# vim: set filetype=sh ts=4 sw=4 sts=4 et:
set -e
umask 077

basedir=$(readlink -f "$(dirname "$0")"/../..)
# shellcheck source=lib/shell/functions.inc
. "$basedir"/lib/shell/functions.inc

if command -v gpg1 >/dev/null 2>&1; then
    gpgcmd="gpg1"
else
    gpgcmd="gpg"
fi

config_list=''
if [ -f "$BASTION_ETC_DIR/osh-backup-acl-keys.conf" ]; then
    config_list="$BASTION_ETC_DIR/osh-backup-acl-keys.conf"
fi
if [ -d "$BASTION_ETC_DIR/osh-backup-acl-keys.conf.d" ]; then
    config_list="$config_list $(find "$BASTION_ETC_DIR/osh-backup-acl-keys.conf.d" -mindepth 1 -maxdepth 1 -type f -name "*.conf" | sort)"
fi

if [ -z "$config_list" ]; then
    _err "No configuration loaded, aborting"
    exit 1
fi

# load the config files only if they're owned by root:root and mode is o-rwx
for file in $config_list; do
    if [ "$(find "$file" -uid 0 -gid 0 ! -perm /o+rwx | wc -l)" = 1 ] ; then
        # shellcheck source=etc/bastion/osh-backup-acl-keys.conf.dist
        . "$file"
    else
        _err "Configuration file not secure ($file), aborting."
        exit 1
    fi
done

# shellcheck disable=SC2153
if [ -n "$LOGFILE" ] ; then
    exec &>> >(tee -a "$LOGFILE")
fi

if [ -z "$DESTDIR" ] ; then
    _err "$0: Missing DESTDIR in configuration, aborting."
    exit 1
fi

if ! echo "$DAYSTOKEEP" | grep -Eq '^[0-9]+$' ; then
    _err "$0: Invalid specified DAYSTOKEEP value ($DAYSTOKEEP), aborting."
    exit 1
fi

_log "Starting backup..."

[ -d "$DESTDIR" ] || mkdir -p "$DESTDIR"

tarfile="$DESTDIR/backup-$(date +'%Y-%m-%d').tar.gz"
_log "Creating $tarfile..."
supp_entries=""
for entry in /root/.gnupg /root/.ssh /var/otp
do
    [ -e "$entry" ] && supp_entries="$supp_entries $entry"
done
# SC2086: we don't want to quote $supp_entries, we want it expanded
# shellcheck disable=SC2086
tar czf "$tarfile" -p --xattrs --acls --one-file-system --numeric-owner \
    --exclude=".encrypt" \
    --exclude="ttyrec" \
    --exclude="*.sqlite" \
    --exclude="*.log" \
    --exclude="*.ttyrec" \
    --exclude="*.ttyrec.*" \
    --exclude="*.gz" \
    --exclude="*.zst" \
    /home/ /etc/passwd /etc/group /etc/shadow /etc/gshadow /etc/bastion /etc/ssh $supp_entries 2>/dev/null; ret=$?
if [ $ret -eq 0 ]; then
    _log "File created"
else
    _err "Error while creating file (sysret=$ret)"
fi

encryption_worked=0
if [ -n "$GPGKEYS" ] ; then
    cmdline=""
    for recipient in $GPGKEYS
    do
        cmdline="$cmdline -r $recipient"
    done
    # just in case, encrypt all .tar.gz files we find in $DESTDIR
    while IFS= read -r -d '' file
    do
        _log "Encrypting $file..."
        rm -f "$file.gpg" # if the gpg file already exists, remove it
        # shellcheck disable=SC2086
        if $gpgcmd --encrypt $cmdline "$file" ; then
            encryption_worked=1
            shred -u "$file" 2>/dev/null || rm -f "$file"
        else
            _err "Encryption failed"
        fi
    done < <(find "$DESTDIR/" -mindepth 1 -maxdepth 1 -type f -name 'backup-????-??-??.tar.gz' -print0)
else
    _warn "$tarfile will not be encrypted! (no GPGKEYS specified)"
fi

# push to remote if needed
if [ -n "$PUSH_REMOTE" ] && [ "$encryption_worked" = 1 ] && [ -r "$tarfile.gpg" ] ; then
    _log "Pushing backup file ($tarfile.gpg) remotely..."
    # shellcheck disable=SC2086
    scp $PUSH_OPTIONS "$tarfile.gpg" "$PUSH_REMOTE"; ret=$?
    if [ $ret -eq 0 ]; then
        _log "Push done"
    else
        _err "Push failed (sysret=$ret)"
    fi
fi

# cleanup
_log "Cleaning up old backups..."
find "$DESTDIR/" -mindepth 1 -maxdepth 1 -type f -name 'backup-????-??-??.tar.gz'     -mtime +"$DAYSTOKEEP" -delete
find "$DESTDIR/" -mindepth 1 -maxdepth 1 -type f -name 'backup-????-??-??.tar.gz.gpg' -mtime +"$DAYSTOKEEP" -delete
_log "Done"
exit 0
