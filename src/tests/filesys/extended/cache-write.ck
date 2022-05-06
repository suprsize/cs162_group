# -*- perl -*-
use strict;
use warnings;
use tests::tests;
use tests::random;
check_expected (IGNORE_EXIT_CODES => 1, [<<'EOF']);
(cache-write) begin
(cache-write) cache writes coalesced!
(cache-write) end
EOF
pass;
