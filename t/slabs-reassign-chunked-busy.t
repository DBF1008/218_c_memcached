#!/usr/bin/env perl
#
# Regression test: a slab page move must never delete a *still-referenced*
# chunked (large) item.
#
# Previously slab_rebalance_active_rescue() could only rescue active
# non-chunked items. When a page being reassigned held an ITEM_CHUNKED item (or
# one of its chunks) that was still referenced by a client, the mover would,
# after busy-looping longer than SLAB_MOVE_MAX_LOOPS, run
# LOGGER_EVICTION + STORAGE_delete() + do_item_unlink() and destroy the object
# outright. That turned a hot key that was only *transiently* busy (e.g. being
# read during a manual page move or an automove) into silent data loss.
#
# The fix leaves active chunked items linked and valid, reports them busy, and
# keeps looping until their references drain -- at which point they are rescued
# normally. This test holds references on chunked items across a page move and
# asserts:
#   1. while held, the items are NOT deleted (slab_reassign_busy_deletes stays
#      flat) even after the mover loops well past SLAB_MOVE_MAX_LOOPS, the page
#      does not move, and every held item is still fetchable and intact;
#   2. once the references are released, the page completes via chunk rescues,
#      still without any busy deletes, and the items remain intact.
#
# Note: crossing SLAB_MOVE_MAX_LOOPS (5000) is inherently time-bound -- the
# mover sleeps up to ~5ms between busy loops -- so part of this test waits on
# the order of ~30s on purpose. That window is exactly where the old code did
# its erroneous delete, so it is what makes this a true before/after
# regression.

use strict;
use warnings;
use Test::More;
use Time::HiRes (); # use fully-qualified calls so we don't clobber builtins
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

# slab_chunk_max=16 -> items larger than 16KB are chunked.
# slab_reassign + slab_automove=0 -> only our manual page moves run.
# no_lru_crawler -> nothing else reaps items underneath us.
my $server = new_memcached('-o no_lru_crawler,slab_reassign,slab_automove=0,slab_chunk_max=16 -m 12');
my $sock = $server->sock;

# These tests rely on the debug-only "debugitem" command to pin a reference on
# an item the way an in-flight client read would. Skip cleanly on non-debug
# builds.
print $sock "debugtime 0\r\n";
my $probe = scalar <$sock>;
plan skip_all => 'requires a MEMCACHED_DEBUG build (debugitem/debugtime)'
    unless defined $probe && $probe =~ /^OK/;

# Patterned value so corruption is detectable; 30000 bytes => chunked item.
my $size = 30000;
my $value = '';
{
    my @chars = ("C".."Z");
    for (1 .. $size) {
        $value .= $chars[rand @chars];
    }
}

# Fill until the first eviction so the chunked slab class owns several pages.
# (Like the other slab-mover tests, we stop at the first eviction, so only the
# very oldest item or two is evicted and low-numbered keys still exist.)
my $stats = mem_stats($sock);
my $count = 1;
while (1) {
    print $sock "set cfoo$count 0 0 $size\r\n$value\r\n";
    my $r = scalar <$sock>;
    last unless $r eq "STORED\r\n";
    my $s_after = mem_stats($sock);
    last if ($s_after->{evictions} > $stats->{evictions});
    $count++;
    last if $count > 100000; # safety valve
}
cmp_ok($count, '>', 50, "stored a useful number of chunked items ($count)");

# Find the chunked data-chunk slab class (the one holding the most pages).
my $sid = 0;
{
    my $s = mem_stats($sock, 'slabs');
    my $total_pages = 0;
    for my $k (keys %$s) {
        next unless $k =~ m/^(\d+):total_pages/;
        if ($s->{$k} > $total_pages) {
            $sid = $1;
            $total_pages = $s->{$k};
        }
    }
}
cmp_ok($sid, '>', 0, "found chunked slab class: $sid");

# Free up a few pages worth of memory from the *newest* keys so the mover has
# somewhere to rescue the (non-held) chunks of the page it is clearing. We move
# the oldest page, so deleting newest keys keeps the page-under-move populated.
my $todelete = int((1024 * 1024) / $size) * 3 + 1;
for (0 .. $todelete) {
    my $i = $count - $_;
    next if $i < 1;
    print $sock "delete cfoo$i\r\n";
    scalar <$sock>; # DELETED or NOT_FOUND; don't care which.
}

# Pin references on a batch of the *oldest* surviving items. Their chunks live
# in the oldest page(s) -- exactly the page the mover clears first -- so it will
# busy-loop on them. Each "debugitem ref" intentionally leaks one reference we
# release later with "debugitem unref".
my @held;
for my $i (3 .. 32) {
    print $sock "debugitem ref cfoo$i\r\n";
    my $r = scalar <$sock>;
    push @held, $i if $r eq "OK\r\n";
}
cmp_ok(scalar @held, '>', 0, "pinned references on " . scalar(@held) . " chunked items");

# Helper: how many of the held items are still present and byte-for-byte intact.
sub held_intact {
    my $ok = 0;
    for my $i (@held) {
        print $sock "get cfoo$i\r\n";
        my $line = scalar <$sock>;
        next if !defined $line || $line =~ /^END/;
        $line .= scalar(<$sock>);
        $line .= scalar(<$sock>);
        $ok++ if $line eq "VALUE cfoo$i 0 $size\r\n$value\r\nEND\r\n";
    }
    return $ok;
}

is(held_intact(), scalar @held, "all held items intact before the page move");

# Kick off a page move out of the chunked class toward the global pool.
$stats = mem_stats($sock);
print $sock "slabs reassign $sid 0\r\n";
is(scalar <$sock>, "OK\r\n", "page move started");

# Watch long enough for the mover to loop well past SLAB_MOVE_MAX_LOOPS (the
# point at which the buggy code deleted the busy chunked items). Fail fast the
# instant any busy delete happens. The fixed code never deletes, so this window
# elapses with busy_deletes flat and the page unmoved.
my $WATCH_SECS = 35;
my $deadline = Time::HiRes::time() + $WATCH_SECS;
my $deleted_during_watch = 0;
my $stats_w = $stats;
while (Time::HiRes::time() < $deadline) {
    $stats_w = mem_stats($sock);
    if ($stats_w->{slab_reassign_busy_deletes} > $stats->{slab_reassign_busy_deletes}) {
        $deleted_during_watch = 1;
        last;
    }
    Time::HiRes::sleep(0.2);
}

is($deleted_during_watch, 0,
    "no busy deletes while chunked items are actively referenced");
is($stats_w->{slab_reassign_busy_deletes}, $stats->{slab_reassign_busy_deletes},
    "slab_reassign_busy_deletes did not increase during the move");
cmp_ok($stats_w->{slab_reassign_busy_items}, '>', $stats->{slab_reassign_busy_items} + 1000,
    "page mover kept busy-looping over the held chunked items");
is($stats_w->{slabs_moved}, $stats->{slabs_moved},
    "page did not move while its chunked items were still referenced");
is(held_intact(), scalar @held,
    "every referenced chunked item survived the busy page move intact");

# Release the references. The items drop to a quiescent refcount and the mover
# can finally rescue them, completing the page move -- still with no deletes.
for my $i (@held) {
    print $sock "debugitem unref cfoo$i\r\n";
    scalar <$sock>;
}

my $RECOVER_SECS = 20;
my $rdeadline = Time::HiRes::time() + $RECOVER_SECS;
my $stats_r = $stats_w;
while (Time::HiRes::time() < $rdeadline) {
    $stats_r = mem_stats($sock);
    last if $stats_r->{slabs_moved} > $stats->{slabs_moved};
    Time::HiRes::sleep(0.1);
}

cmp_ok($stats_r->{slabs_moved}, '>', $stats->{slabs_moved},
    "page move completed once references were released");
cmp_ok($stats_r->{slab_reassign_chunk_rescues}, '>', $stats->{slab_reassign_chunk_rescues},
    "chunked item chunks were rescued (not deleted)");
is($stats_r->{slab_reassign_busy_deletes}, $stats->{slab_reassign_busy_deletes},
    "still no busy deletes after the page completed");
is(held_intact(), scalar @held,
    "all previously-referenced chunked items are still intact after rescue");

done_testing();
