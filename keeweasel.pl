#!/usr/bin/perl
use strict;
use warnings;

use Inline C => "DATA",
    LIBS => "-lnss3",
    INC => "-I/usr/include/nspr";

use MIME::Base64;
use DBI;
use File::Spec;
use Storable;
use File::KeePass;
use Digest::SHA1 qw(sha1);

my $profdir = "/home/yath/ffkey";
my $kpdbfile = "/tmp/foo.kdb";
my $kpdbpass = "foo";
my $defgroup = "Firefox";

my $kpchanged = 0;

BEGIN {
    for my $s (qw(NSS_Init PK11SDR_Decrypt PK11SDR_Encrypt)) {
        eval qq{sub $s { goto &C_$s }};
    }
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
#    print "----> INFO\n";
#    use Data::Dumper; print Dumper $_[0];
    $_[0] =~ /^#keeweasel#(\d+)#([A-Za-z0-9+\/_=\r\n-]+)/ or die "Unable to fetch info";
    $1 == 1 or die "Unknown version $1";
    return Storable::thaw(decode_base64($2));
}

sub open_firefox_db {
    my $dbh = DBI->connect("dbi:SQLite:dbname=".
                                File::Spec->catfile($profdir, "signons.sqlite"),
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
    my $k = File::KeePass->new;
    if ($File::KeePass::VERSION <= 0.03) {
        # workaround for CPAN bug #67534
        open (my $fh, "<", $kpdbfile) || die "Unable to open $kpdbfile: $!";
        binmode($fh) || die "Unable to set $kpdbfile to binary mode: $!";
        my $buf = do { local $/; <$fh> };
        close($fh);
        $k->parse_db($buf, $kpdbpass);
    } else {
        $k->load_db($kpdbfile, $kpdbpass);
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
    NSS_Init($profdir);
    my $ffdb = open_firefox_db();
    my $kpdb = open_keepass_db();
    sync_pws($kpdb, $ffdb);
    save_keepass_db($kpdb, $kpdbfile, $kpdbpass) if $kpchanged;
#    print PK11SDR_Decrypt("fooafasfsadpofisapof");
}

main

__DATA__
__C__
#include <nss/nss.h>
#include <nss/pk11sdr.h>
#include <nspr/nspr.h>

static unsigned char default_key[] = {
    0xF8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

#define LAST_ERROR PR_ErrorToString(PR_GetError(), PR_LANGUAGE_I_DEFAULT)

int C_NSS_Init(char *path) {
    if (NSS_Init(path) != SECSuccess)
        Perl_croak(aTHX_ "NSS_Init: %s", LAST_ERROR);
}

SV *C_PK11SDR_Decrypt(SV *enc) {
    SECItem si_enc, si_dec;

    si_enc.type = siBuffer;
    si_enc.data = SvPV(enc, si_enc.len);

    char *err = NULL;

    if (PK11SDR_Decrypt(&si_enc, &si_dec, NULL) != SECSuccess) {
        Perl_croak(aTHX_ "Something went wrong");
    }

    SV *ret = newSVpvn(si_dec.data, si_dec.len);
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
            Perl_croak(aTHX_ "Usage: PK11SDR_Encrypt(decrypted [, key ID])");
            break;
    }

    si_key.type = siBuffer;
    if (SvOK(key)) {
        si_key.data = SvPV(key, si_key.len);
    } else {
        si_key.data = default_key;
        si_key.len  = sizeof(default_key);
    }

    si_dec.type = siBuffer;
    si_dec.data = SvPV(decrypted, si_dec.len);

    if (PK11SDR_Encrypt(&si_key, &si_dec, &si_enc, NULL) != SECSuccess)
        Perl_croak(aTHX_ "Something went wrong");

    SV *ret = newSVpvn(si_enc.data, si_enc.len);
    SECITEM_FreeItem(&si_enc, 0);

    return ret;
}
