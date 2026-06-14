#!/usr/bin/env perl
# Regression test for reading back oversized chunked extstore objects.
#
# When a chunked object stored in extstore needs more iovecs than IOV_MAX to
# assemble its read response, storage_get_item() must report a distinct
# "too big" failure instead of masquerading as out-of-memory. Previously both
# the real OOM path and the IOV_MAX/read-plan failure returned -1, so callers
# counted everything as get_oom_extstore and replied "out of memory", which
# misled monitoring and blurred the two failure modes across protocols.

use strict;
use warnings;

use Test::More;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

my $ext_path;

if (!supports_extstore()) {
    plan skip_all => 'extstore not enabled';
    exit 0;
}

$ext_path = "/tmp/extstore.$$";

# slab_chunk_max=1 forces 1KB chunks, so a multi-MB value is split into far more
# than IOV_MAX (1024 on Linux) chunks. Reading it back from extstore therefore
# trips the iovec limit rather than running out of memory.
my $server = new_memcached("-m 64 -I 3m -U 0 -o ext_page_size=8,ext_wbuf_size=4,ext_threads=1,ext_io_depth=2,ext_item_size=512,ext_item_age=0,ext_recache_rate=0,ext_max_frag=0,ext_path=$ext_path:64m,slab_chunk_max=1,slab_automove=0,ext_max_sleep=100000");
my $sock = $server->sock;

# Keep the object on disk: don't let compaction move/evict it out from under us.
print $sock "extstore compact_under 0\r\n";
is(scalar <$sock>, "OK\r\n", "disabled compaction");

# Wait until the big item has flushed out of memory and onto extstore. The item
# is chunked, so it's linked into the largest slab class LRU; once flushed it is
# replaced by a small on-disk header (a low slab class we can ignore). It's the
# only item stored, so an empty big class means our item is on disk.
sub wait_for_ext {
    my $tries = shift // 60;
    while ($tries-- > 0) {
        my $s = mem_stats($sock, "items");
        my $sum = 0;
        for my $key (keys %$s) {
            if ($key =~ m/items:(\d+):number/) {
                # Ignore classes too small to hold our big item (e.g. the header).
                next if $1 < 3;
                $sum += $s->{$key};
            }
        }
        return 1 if $sum == 0;
        sleep 1;
    }
    return 0;
}

# A ~2MB value: with 1KB chunks this needs ~2000 iovecs to read back, well over
# the IOV_MAX limit, but it still stores and flushes fine.
my $size = 2 * 1024 * 1024;
my $data = "x" x $size;
print $sock "set bigkey 0 0 $size\r\n$data\r\n";
is(scalar <$sock>, "STORED\r\n", "stored oversized chunked item");

ok(wait_for_ext(), "oversized item flushed to extstore");

# The read must fail as "too big", not as OOM, and the stats must reflect that.
{
    print $sock "get bigkey\r\n";
    my $res = <$sock>;
    $res =~ s/[\r\n]//g;
    is($res, 'SERVER_ERROR object too large for read response',
        'oversized read reports a too-big error, not OOM');

    my $stats = mem_stats($sock);
    is($stats->{get_too_big_extstore}, 1, 'too-big read counter incremented');
    is($stats->{get_oom_extstore}, 0, 'oom counter was not touched');
}

done_testing();

END {
    unlink $ext_path if $ext_path;
}
