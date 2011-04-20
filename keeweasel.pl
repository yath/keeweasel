#!/usr/bin/perl
use strict;
use warnings;

sub WINDOWS() { $^O eq "MSWin32" }

use Inline C => "DATA",
    CCFLAGS => "-W -Wall -Wno-unused-variable -Wno-unused-parameter -Wno-comment",
    BUILD_NOISY => 1,
    WINDOWS ?
    () :
    (LIBS => "-lnss3",
     INC => "-I/usr/include/nspr");

use MIME::Base64;
use DBI;
use File::Spec::Functions qw(catfile);
use Storable;
use File::KeePass;
use Digest::SHA1 qw(sha1);
use Getopt::Long qw(:config no_auto_abbrev bundling);

# comand-line options
my $ffprofile;
my $kpdbfile;
my $kpdbpass;
my $defgroup;

my $kpchanged = 0;

BEGIN {
    for my $s (qw(NSS_Init NSS_InitReadWrite NSS_Shutdown
                  PK11SDR_Decrypt PK11SDR_Encrypt
                  install_pw_handler
                  win_init win_set_echo)) {
        eval qq{sub $s { goto &C_$s }};
    }

    require Term::ReadKey unless WINDOWS;
}

sub DEBUG {
    warn "@_\n";
}

sub encode_base64_oneline {
    my $ret = encode_base64($_[0]);
    $ret =~ s/[\r\n]//g;
    return $ret;
}

sub storeinfo {
    my $base64 = encode_base64_oneline(Storable::freeze($_[0]));
    return "#keeweasel#1#".$base64."#";
}

sub fetchinfo {
    $_[0] =~ /^#keeweasel#(\d+)#([A-Za-z0-9+\/_=\r\n-]+)/ or die "Unable to fetch info";
    $1 == 1 or die "Unknown version $1";
    return Storable::thaw(decode_base64($2));
}

sub get_firefox_profdir {
    my ($profname) = @_;

    my $path = do {
        if ($profname && -d $profname) {
            # if $profname is a directory use that
            $profname
        } else {
            my $ffroot = catfile(WINDOWS ?
                ($ENV{APPDATA}, "Mozilla", "Firefox") :
                ($ENV{HOME}, ".mozilla", "firefox"));

            open(my $fh, "<", catfile($ffroot, "profiles.ini")) or
                die "Unable to open profiles.ini: $!";

            my %profiles;
            my $section;
            while (<$fh>) {
                s/[\s\r\n]+$//;
                next if /^$/;
                if (/^\[(.*?)\]$/) {
                    $section = $1;
                } elsif (/^(\w+)=(.*)$/) {
                    die "key-value pair not in any section" unless $section;
                    $profiles{$section}->{$1} = $2;
                } else {
                    warn "unknown line: $_";
                }
            }
            close($fh);

            my @profiles = grep { ($profname && exists $profiles{$_}->{Name}) ?
                                  (lc $profiles{$_}->{Name} eq $profname) :
                                  $profiles{$_}->{Default}
                                 } keys %profiles;
            die "More than one matching firefox profile found" if @profiles > 1;

            # if only one profile is defined use that one
            @profiles = grep /^Profile\d+$/, keys %profiles unless @profiles;

            die "No default firefox profile found" unless @profiles == 1;

            my %p = %{$profiles{$profiles[0]}};

            $p{IsRelative} ? catfile($ffroot, $p{Path}) : $p{Path}
        } # -d $profdir
    }; # $path = do {

    foreach (qw(key3.db signons.sqlite)) {
        my $fn = catfile($path, $_);
        die "$fn is not readable" unless -r $fn;
    }

    return $path;
}

sub set_terminal_echo {
    my ($echo) = @_;
    if (WINDOWS) {
        win_set_echo($echo);
    } else {
        Term::ReadKey::ReadMode($echo ? "restore" : "noecho");
    }
}

my %passcache; # cached passwords
sub ask_pass {
    my ($obj, $prompt) = @_;
    return $passcache{$obj} if exists $passcache{$obj};

    print $prompt;

    set_terminal_echo(0);
    my $ret = <>;
    set_terminal_echo(1);
    print "\n";

    chomp $ret;
    $passcache{$obj} = $ret;

    return $ret;
}

sub open_firefox_db {
    my ($profdir) = @_;
    my $dbh = DBI->connect("dbi:SQLite:dbname=".
                                catfile($profdir, "signons.sqlite"),
                           "", "", { RaiseError => 1 });
    return $dbh;
}

sub get_firefox_pws {
    my $dbh = shift;
    my $ret = $dbh->selectall_hashref("select * from moz_logins", "guid");

    foreach my $key (keys %$ret) {
        $ret->{$key}->{_username} = $ret->{$key}->{encType} == 1 ?
            PK11SDR_Decrypt(decode_base64($ret->{$key}->{encryptedUsername})) :
            decode_base64($ret->{$key}->{encryptedUsername});
        $ret->{$key}->{_password} = $ret->{$key}->{encType} == 1 ?
            PK11SDR_Decrypt(decode_base64($ret->{$key}->{encryptedPassword})) :
            decode_base64($ret->{$key}->{encryptedPassword});

        $ret->{$key}->{_id} = $ret->{$key}->{id};
        delete $ret->{$key}->{$_} foreach qw(encryptedUsername encryptedPassword id);
    }

    return $ret;
}

sub add_firefox_pw {
    my ($dbh, $info) = @_;

    $info->{encryptedUsername} = $info->{encType} == 1 ?
        encode_base64_oneline(PK11SDR_Encrypt($info->{_username})) :
        encode_base64_oneline($info->{_username});

    $info->{encryptedPassword} = $info->{encType} == 1 ?
        encode_base64_oneline(PK11SDR_Encrypt($info->{_password})) :
        encode_base64_oneline($info->{_password});

    my @keys = grep !/^_/, keys %$info;
    $dbh->do("insert into moz_logins(".join(",", @keys).") values (".join(",", ("?")x@keys).")",
        undef, map { $info->{$_} } @keys) or die $DBI::errstr;
}

sub open_keepass_db {
    my ($filename, $password) = @_;
    my $k = File::KeePass->new;
    if ($File::KeePass::VERSION <= 0.03) {
        # workaround for CPAN bug #67534
        open (my $fh, "<", $filename) || die "Unable to open $filename: $!";
        binmode($fh) || die "Unable to set $kpdbfile to binary mode: $!";
        my $buf = do { local $/; <$fh> };
        close($fh);
        $k->parse_db($buf, $password);
    } else {
        $k->load_db($filename, $password);
    }
    $k->unlock;
    return $k;
}

sub save_keepass_db {
    my ($kpdb, $kpdbfile, $kpdbpass) = @_;

    # check whether File::KeePass is affected by cpan bug #67553
    eval {
        my $tmpfkp = File::KeePass->new();
        my $group = { title => "keeweaseltest".time() };
        $tmpfkp->add_group($group);
        ($tmpfkp->find_groups($group))[0]->{unknown}->{23} = "\x68\x61\x69\x6c\x00\x65\x72\x69\x73";
        my $buf = $tmpfkp->gen_db("fnord");
        $tmpfkp = File::KeePass->new();
        $tmpfkp->parse_db($buf, "fnord");
        die "size mismatch" if length(($tmpfkp->find_groups($group))[0]->{unknown}->{23}) != 7;
    };

    if ($@) {
        warn "Your version of File::KeePass is affected by cpan bug #67553.\n".
             "keeweasel will try to work around this issue.\n";
        foreach my $group ($kpdb->find_groups({})) {
            $group->{unknown}->{$_} = pack("L", length($group->{unknown}->{$_})).$group->{unknown}->{$_}
                foreach keys %{$group->{unknown}};
            foreach my $item ($group->{items}) {
                $item->{unknown}->{$_} = pack("L", length($item->{unknown}->{$_})).$item->{unknown}->{$_}
                    foreach keys %{$item->{unknown}};
            }
        }
    }

    my $tempfile = $kpdbfile.".keeweasel.tmp.".int(time());

    if ($File::KeePass::VERSION <= 0.03) {
        # workaround for CPAN bug #67534
        open(my $fh, ">", $tempfile) || die "Unable to open $tempfile: $!";
        binmode($fh) || die "Unable to set $kpdbfile to binary mode: $!";
        print $fh $kpdb->gen_db($kpdbpass);
        close($fh) || die "Unable to close $tempfile: $!";
    } else {
        $kpdb->save_db($tempfile, $kpdbpass);
    }

    # try loading the file, just in case...
    open_keepass_db($tempfile, $kpdbpass) || die "Unable to read $tempfile";

    rename($tempfile, $kpdbfile) || die "Unable to rename $tempfile to $kpdbfile: $!";
}

sub get_keepass_pws {
    my ($group, $ret) = @_;

    foreach my $entry (@{$group->{entries}}) {
        $entry->{comment} =~ /^#keeweasel#/ or next;
        my $info = fetchinfo($entry->{comment});
        push(@{$ret->{$info->{guid}}}, {
            info => $info,
            entry => $entry,
            group => $group
        });
    }

    get_keepass_pws($_, $ret) foreach @{$group->{groups}};
}

sub add_keepass_pw {
    my ($kpdb, $ffentry, $group, $template) = @_;
    my $new = {
        comment => storeinfo({%$ffentry, _last_keepass_pw => sha1($ffentry->{_username}.":".$ffentry->{_password})}),
        title => $ffentry->{hostname},
        url => $ffentry->{hostname},
        username => $ffentry->{_username},
        password => $ffentry->{_password},
        group => $group,
    };

    if ($template) {
        $new->{$_} = $template->{$_} foreach grep !/^(_|username$|password$|comment$|id$|group$)/, keys %$template;
    }

    $kpdb->add_entry($new);

    $kpchanged = 1;
}

sub compare_entries {
    my ($kpentry, $kpdb, $ffentry, $ffdb) = @_;

    if (!$ffentry) {
        DEBUG("$kpentry->{info}->{guid} is new to firefox, adding...");
        add_firefox_pw($ffdb, $kpentry->{info});
    } elsif (!$kpentry) {
        DEBUG("$ffentry->{guid} is new to keepass, adding...");
        add_keepass_pw($kpdb, $ffentry, ($kpdb->find_group({title => $defgroup}))[0]);
    } elsif ($ffentry->{timePasswordChanged} > $kpentry->{info}->{timePasswordChanged}) {
        DEBUG("password changed in firefox for $ffentry->{guid}, updating in keepass...");
        add_keepass_pw($kpdb, $ffentry, $kpdb->{group}, $kpdb->{entry});
        $kpdb->delete_entry({id => $kpentry->{entry}->{id}});
    } elsif ($kpentry->{info}->{timePasswordChanged} > $ffentry->{timePasswordChanged}) {
        DEBUG("password changed in keepass for $ffentry->{guid}, updating in firefox...");
        add_firefox_pw($ffdb, $kpentry->{info});
        $ffdb->do("delete from moz_logins where id = ?", undef, $ffentry->{_id})
            or die "Unable to delete login: $DBI::errstr";
    }
}

sub sync_pws {
    my ($kpdb, $ffdb) = @_;

    my $ffpws = get_firefox_pws($ffdb);
    my $kppws = {};
    get_keepass_pws($_, $kppws) foreach @{$kpdb->groups};

    my %all_guids = map { $_ => 1 } (keys %$ffpws, keys %$kppws);

    foreach my $guid (keys %all_guids) {
        # force an undef entry on either side to make sure compare_entries
        # gets called
        push(@{$kppws->{$guid}}, undef) unless
            exists($kppws->{$guid}) && @{$kppws->{$guid}};

        $ffpws->{$guid} = undef unless exists $ffpws->{$guid};

        compare_entries($_, $kpdb, $ffpws->{$guid}, $ffdb)
            foreach @{$kppws->{$guid}};
    }
}

sub main {
    GetOptions("p|ffprofile=s"  => \$ffprofile,
               "k|keepassdb=s"  => \$kpdbfile,
               "d|defgroup=s"   => \$defgroup,
               "P|kpdbpass=s"   => \$kpdbpass
    );

    die "KeePass DB file required" unless $kpdbfile;

    win_init if WINDOWS;

    my $ffprofdir = get_firefox_profdir($ffprofile);
    DEBUG("using firefox profile $ffprofdir");

    install_pw_handler();
    NSS_Init($ffprofdir);

    # do an NSS call to check for common errors and trigger password prompt
    # if necessary
    eval { PK11SDR_Encrypt("test"); };
    if ($@ && $@ =~ /SEC_ERROR_READ_ONLY/) {
        # PK11SDR_Encrypt failed with SEC_ERROR_READ_ONLY, this happens when no key
        # has been generated yet in the key3.db and PK11SDR_Encrypt tries to generate
        # one. re-init NSS read-write in this case.
        NSS_Shutdown();
        NSS_InitReadWrite($ffprofdir);
        print "Your key3.db will probably be updated - restart Firefox soon!\n";
    } elsif ($@ && $@ =~ /SEC_ERROR_BAD_PASSWORD/) {
        # wrong password
        die "Firefox password is incorrect";
    } elsif ($@) {
        die $@; # any other error
    }

    my $ffdb = open_firefox_db($ffprofdir);

    $kpdbpass = ask_pass($kpdbfile, "Enter password for KeePass DB: ") unless $kpdbpass;
    my $kpdb = eval { open_keepass_db($kpdbfile, $kpdbpass) };
    if ($@ && $@ =~ /file checksum did not match/) {
        die "KeePass password is incorrect or file is corrupted";
    } elsif ($@) {
        die $@;
    }

    sync_pws($kpdb, $ffdb);
    save_keepass_db($kpdb, $kpdbfile, $kpdbpass) if $kpchanged;
}

main

__DATA__
__C__
#define UNUSED(x) PERL_UNUSED_VAR(x)

#ifdef WIN32
#include <windows.h>
#include <Strsafe.h>

#define BUFSIZE 1024
#define FF_REGKEY TEXT("SOFTWARE\\Mozilla\\Mozilla Firefox")

/******* BEGIN NSS/NSPR DEFINITIONS *******/

typedef enum {
    siBuffer = 0
    /* rest omitted */
} SECItemType;

typedef enum {
    SECWouldBlock = -2,
    SECFailure = -1,
    SECSuccess = 0
} SECStatus;

typedef struct {
    SECItemType type;
    unsigned char *data;
    unsigned int len;
} SECItem;

typedef int PRBool;
typedef int PRErrorCode;
typedef struct PK11SlotInfoStr PK11SlotInfo;
typedef char *(*PK11PasswordFunc)(PK11SlotInfo *slot, PRBool retry, void *arg);

SECStatus   (*NSS_Init)(const char *);
SECStatus   (*NSS_InitReadWrite)(const char *);
SECStatus   (*NSS_Shutdown)(void);
SECStatus   (*PK11SDR_Encrypt)(SECItem *, SECItem *, SECItem *, void *);
SECStatus   (*PK11SDR_Decrypt)(SECItem *, SECItem *, void *);
void        (*PK11_SetPasswordFunc)(PK11PasswordFunc func);
void        (*SECITEM_FreeItem)(SECItem *, PRBool);
PRErrorCode (*PR_GetError)(void);
char *      (*PL_strdup)(const char *);

#define SEC_ERROR_BAD_PASSWORD  -8177
#define SEC_ERROR_READ_ONLY     -8126

/******* END NSS/NSPR DEFINITIONS *******/

LPTSTR getRegKey(HKEY key, LPCTSTR subkey, LPCTSTR value) {
    HKEY h_subkey;
    static TCHAR data[BUFSIZE];
    DWORD type;
    DWORD cb_data = sizeof(data);

    LONG rc = RegOpenKeyEx(
        key,        // hKey
        subkey,     // lpSubkey
        0,          // ulOptions
        KEY_READ,   // samDesired
        &h_subkey   // phkResult
    );
    if (rc != ERROR_SUCCESS)
        return NULL;

    rc = RegQueryValueEx(
        h_subkey,       // hKey
        value,          // lpValueName
        NULL,           // lpReserved
        &type,          // lpType
        (LPBYTE)data,   // lpData
        &cb_data        // lpCbData
    );

    RegCloseKey(h_subkey);

    if (rc != ERROR_SUCCESS)
        return NULL;

    if (type != REG_SZ)
        croak("%s is not a REG_SZ?!", subkey);

    return data;
}

LPTSTR getFirefoxDirectory() {
    LPTSTR ffversion = getRegKey(HKEY_LOCAL_MACHINE, FF_REGKEY, TEXT("CurrentVersion"));
    if (!ffversion)
        croak("Unable to open HKLM\\%s\\CurrentVersion: %d", FF_REGKEY, (int)GetLastError());

    TCHAR ffkeypath[BUFSIZE];
    if (StringCchPrintf(ffkeypath, sizeof(ffkeypath), TEXT("%s\\%s\\Main"), FF_REGKEY, ffversion) != S_OK)
        croak("StringCchPrintf failed");

    LPTSTR ffdir = getRegKey(HKEY_LOCAL_MACHINE, ffkeypath, TEXT("Install Directory"));
    if (!ffdir)
        croak("Unable to open HKLM\\%s\\Install Directory: %d", ffkeypath, (int)GetLastError());

    return ffdir;
}

void C_win_init() {
#define LOAD(name, fatal) \
        if (StringCchPrintf(dllpath, sizeof(dllpath), TEXT("%s\\%s.dll"), ffdir, #name) != S_OK) \
            croak("StringCchPrintf failed for " #name ".dll"); \
        HMODULE dll_ ## name = LoadLibrary(dllpath); \
        if (fatal && ! dll_ ## name) \
            croak("LoadLibrary(\"" #name ".dll\") failed: %d", (int)GetLastError());

#define IMPORT(dll, func) do { \
        if (!(func = (void *)GetProcAddress(dll_ ## dll, #func))) \
            croak("GetProcAddress(" #dll ", \"" #func "\") failed: %d", (int)GetLastError()); \
        } while(0)

    LPTSTR ffdir = getFirefoxDirectory();
    TCHAR dllpath[BUFSIZE];

    LOAD(mozcrt19,    0)
    LOAD(nspr4,       1)
    LOAD(plc4,        1)
    LOAD(plds4,       0)
    LOAD(nssutil3,    0)
    LOAD(sqlite3,     0)
    LOAD(mozsqlite3,  0)
    LOAD(softokn3,    0)
    LOAD(nss3,        1)

    IMPORT(nss3,  NSS_Init);
    IMPORT(nss3,  NSS_InitReadWrite);
    IMPORT(nss3,  NSS_Shutdown);
    IMPORT(nss3,  PK11SDR_Encrypt);
    IMPORT(nss3,  PK11SDR_Decrypt);
    IMPORT(nss3,  PK11_SetPasswordFunc);
    IMPORT(nss3,  SECITEM_FreeItem);
    IMPORT(nspr4, PR_GetError);
    IMPORT(plc4,  PL_strdup);
}

void C_win_set_echo(SV *echo) {
    DWORD mode;
    HANDLE console;

    if (!(console = GetStdHandle(STD_INPUT_HANDLE)))
        croak("Unable to get STD_INPUT_HANDLE: %d", (int)GetLastError());

    if (!GetConsoleMode(console, &mode))
        croak("GetConsoleMode failed: %d", (int)GetLastError());

    if (SvTRUE(echo))
        mode |= ENABLE_ECHO_INPUT;
    else
        mode &= ~ENABLE_ECHO_INPUT;

    if (!SetConsoleMode(console, mode))
        croak("SetConsoleMode failed: %d", (int)GetLastError());
}

#else /* WIN32 */

#include <nss/nss.h>
#include <nss/pk11sdr.h>
#include <nss/secerr.h>
#include <nss/secmodt.h>
#include <nss/pk11pub.h>
#include <nspr/nspr.h>

void C_win_init() {
    croak("win_init makes only sense on WIN32");
}

void C_win_set_echo(SV *echo) {
    UNUSED(echo);
    croak("win_set_echo makes only sense on WIN32");
}

#endif /* WIN32 */

char *last_db = NULL;

char *pk11_pw_handler(PK11SlotInfo *slot, PRBool retry, void *arg) {
    dSP;
    int count;
    SV *pass;
    char *ret;

    UNUSED(slot);
    UNUSED(arg);

    if (retry)
        return NULL;

    if (!last_db)
        croak("pk11_pw_handler called without an open database");

    ENTER;
    SAVETMPS;

    PUSHMARK(SP);
    XPUSHs(sv_2mortal(newSVpv(last_db, 0)));
    XPUSHs(sv_2mortal(newSVpvs("Enter password for Firefox DB: ")));
    PUTBACK;

    count = call_pv("ask_pass", G_SCALAR);

    SPAGAIN;

    if (count != 1)
        croak("Uhm, ask_pass() didn't return exactly 1 but %d", count);

    pass = POPs;
    ret = PL_strdup(SvPV_nolen(pass));

    PUTBACK;
    FREETMPS;
    LEAVE;

    return ret;
}

void C_install_pw_handler() {
    PK11_SetPasswordFunc(pk11_pw_handler);
}

void C_NSS_Init(char *path) {
    if (NSS_Init(path) != SECSuccess)
        croak("NSS_Init(\"%s\") failed: %d", path, PR_GetError());
    last_db = path;
}

void C_NSS_InitReadWrite(char *path) {
    if (NSS_InitReadWrite(path) != SECSuccess)
        croak("NSS_InitReadWrite(\"%s\") failed: %d", path, PR_GetError());
    last_db = path;
}

void C_NSS_Shutdown() {
    if (NSS_Shutdown() != SECSuccess)
        croak("NSS_Shutdown() failed: %d", PR_GetError());
    last_db = NULL;
}

SV *C_PK11SDR_Decrypt(SV *enc) {
    SECItem si_enc, si_dec;

    si_enc.type = siBuffer;
    si_enc.data = (unsigned char *)SvPV(enc, si_enc.len);

    if (PK11SDR_Decrypt(&si_enc, &si_dec, NULL) != SECSuccess)
        croak("PK11SDR_Decrypt(encrypted, decrypted, NULL) failed: %d", PR_GetError());

    SV *ret = newSVpvn((char *)si_dec.data, si_dec.len);
    SECITEM_FreeItem(&si_dec, 0);

    return ret;
}

SV *C_PK11SDR_Encrypt(SV *decrypted, ...) {
    Inline_Stack_Vars;
    SECItem si_key, si_dec, si_enc;
    SV *key;

    switch (Inline_Stack_Items) {
        case 1:
            key = &PL_sv_undef;
            break;
        case 2:
            key = Inline_Stack_Item(1);
            break;
        default:
            croak("Usage: PK11SDR_Encrypt(decrypted [, key ID])");
            break;
    }

    si_key.type = siBuffer;
    if (SvOK(key)) {
        si_key.data = (unsigned char *)SvPV(key, si_key.len);
    } else {
        si_key.len = 0;
    }

    si_dec.type = siBuffer;
    si_dec.data = (unsigned char *)SvPV(decrypted, si_dec.len);

    if (PK11SDR_Encrypt(&si_key, &si_dec, &si_enc, NULL) != SECSuccess) {
        PRErrorCode err = PR_GetError();
        // put known common error codes into the error message so the caller
        // can handle then
        croak("PK11SDR_Encrypt(key, decrypted, encrypted, NULL) failed: %d%s", err,
            (err == SEC_ERROR_READ_ONLY)    ? " (SEC_ERROR_READ_ONLY)"    :
            (err == SEC_ERROR_BAD_PASSWORD) ? " (SEC_ERROR_BAD_PASSWORD)" :
            "");
    }

    SV *ret = newSVpvn((char *)si_enc.data, si_enc.len);
    SECITEM_FreeItem(&si_enc, 0);

    return ret;
}
