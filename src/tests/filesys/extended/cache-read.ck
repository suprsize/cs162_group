# -*- perl -*-
use strict;
use warnings;
use tests::tests;
use tests::random;
check_expected (IGNORE_EXIT_CODES => 1, [<<'EOF']);
(cache-read) begin
(cache-read) retrieved from cache!
(cache-read) end
EOF
pass;
