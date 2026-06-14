#!/usr/bin/env perl
# Regression test: slab reassign must not delete active chunked items.
#
# Before the fix, slab_rebalance_active_rescue() would forcibly delete
# (LOGGER_EVICTION + STORAGE_delete + do_item_unlink) any chunked item
# still referenced by clients once busy_loops exceeded SLAB_MOVE_MAX_LOOPS.
# This caused spurious hot-key loss during page migration.
#
# This test fills memory with large chunked items, triggers slab reassignment
# while concurrently reading them (keeping items busy), and verifies:
#   1. No busy_deletes occur (chunked items are never forcibly evicted).
#   2. Items remain retrievable after rebalance completes.

use strict;
use warnings;
use Test::More tests => 8;
use FindBin qw($Bin);
use lib "$Bin/lib";
use MemcachedTest;

# slab_chunk_max=4 forces items > 4k to be chunked across multiple chunks.
# slab_reassign + slab_automove enable page migration.
my $server = new_memcached('-m 64 -o slab_reassign,slab_automove,lru_crawler,lru_maintainer,slab_chunk_max=4');
my $sock = $server->sock;

# Create a large value that will be chunked (11k with chunk max 4k).
my $value;
{
    my @chars = ("A".."Z");
    for (1 .. 11000) {
        $value .= $chars[rand @chars];
    }
}
my $keycount = 4000;

# Fill memory with chunked items.
for (1 .. $keycount) {
    print $sock "set bigkey$_ 0 0 11000 noreply\r\n$value\r\n";
}

{
    my $stats = mem_stats($sock);
    cmp_ok($stats->{curr_items}, '>', 2000,
        "stored a good number of chunked items: " . $stats->{curr_items});
}

# Record stats before reassignment.
my $stats_before = mem_stats($sock);
my $busy_deletes_before = $stats_before->{slab_reassign_busy_deletes} || 0;

# Open a second connection to hammer reads during rebalance.
# This keeps chunked items "busy" (refcount > 2) while the mover runs.
my $reader = $server->new_sock;
my $reader_running = 1;

# Fork a child process to continuously read items during rebalance.
my $reader_pid = fork();
if ($reader_pid == 0) {
    # Child: hammer reads on the second connection.
    close $sock;
    for (1 .. 5000) {
        my $k = int(rand($keycount)) + 1;
        print $reader "get bigkey$k\r\n";
        my $line = scalar(<$reader>);
        if ($line =~ /^VALUE/) {
            # consume the value + END lines
            scalar(<$reader>);
            scalar(<$reader>);
        }
        # also handle END for misses
    }
    close $reader;
    exit(0);
}
close $reader;

# Give the reader a moment to start hitting items.
sleep 1;

# Trigger slab reassignment: move pages from the chunked-item slab class
# back to global pool. This forces the mover to process pages containing
# active chunked items.
{
    my $s = mem_stats($sock, 'slabs');
    my $max_pages = 0;
    my $scls = 0;
    for my $k (keys %$s) {
        next unless $k =~ m/^(\d+)\:total_pages/;
        if ($s->{$k} > $max_pages) {
            $max_pages = $s->{$k};
            $scls = $1;
        }
    }
    # Issue several reassign requests to move pages.
    for (1 .. 3) {
        print $sock "slabs reassign $scls 0\r\n";
        my $res = scalar(<$sock>);
        sleep 2;
    }
}

# Wait for the reader child to finish.
waitpid($reader_pid, 0);

# Wait a bit for rebalance to settle.
sleep 3;

# KEY CHECK 1: busy_deletes must NOT have increased.
# With the bug, the mover would delete chunked items after SLAB_MOVE_MAX_LOOPS.
{
    my $stats = mem_stats($sock);
    my $busy_deletes_after = $stats->{slab_reassign_busy_deletes} || 0;
    my $delta = $busy_deletes_after - $busy_deletes_before;
    is($delta, 0,
        "no busy_deletes during chunked item rebalance (delta=$delta)");
}

# KEY CHECK 2: Verify that surviving items are still retrievable and correct.
my $hits = 0;
my $misses = 0;
my $corrupt = 0;
for (1 .. $keycount) {
    print $sock "get bigkey$_\r\n";
    my $line = scalar(<$sock>);
    if ($line =~ /^END/) {
        $misses++;
        next;
    }
    # Read value line + END
    my $vline = scalar(<$sock>);
    my $end = scalar(<$sock>);
    if ($vline eq "$value\r\n" && $end eq "END\r\n") {
        $hits++;
    } else {
        $corrupt++;
    }
}

is($corrupt, 0, "no corrupted chunked items after rebalance");
cmp_ok($hits, '>', 0, "at least some chunked items survived rebalance ($hits hits)");

# Verify chunk rescues did happen (non-busy chunks get rescued normally).
{
    my $stats = mem_stats($sock);
    cmp_ok($stats->{slab_reassign_chunk_rescues}, '>', 0,
        "chunk rescues happened during rebalance");
}

# Verify that the global page pool grew (pages were actually moved).
{
    my $stats = mem_stats($sock);
    cmp_ok($stats->{slab_global_page_pool}, '>', 0,
        "global page pool grew after reassignment");
}

# Additional sanity: reassign more pages and re-check no busy_deletes.
{
    print $sock "slabs reassign 17 0\r\n";
    my $res = scalar(<$sock>);
    sleep 2;

    my $stats = mem_stats($sock);
    my $busy_deletes_final = $stats->{slab_reassign_busy_deletes} || 0;
    my $total_delta = $busy_deletes_final - $busy_deletes_before;
    is($total_delta, 0,
        "cumulative busy_deletes still zero after multiple reassignments");
}

# Final check: items still readable.
{
    my $final_hits = 0;
    for (1 .. $keycount) {
        print $sock "get bigkey$_\r\n";
        my $line = scalar(<$sock>);
        if ($line =~ /^VALUE/) {
            scalar(<$sock>);
            scalar(<$sock>);
            $final_hits++;
        }
    }
    cmp_ok($final_hits, '>', 0,
        "chunked items still retrievable after all reassignments ($final_hits hits)");
}
