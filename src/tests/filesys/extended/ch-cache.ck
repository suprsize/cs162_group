# -*- perl -*-
use strict;
use warnings;
use tests::tests;
use tests::random;
check_expected (IGNORE_EXIT_CODES => 1, [<<'EOF']);
(ch-cache) begin
(ch-cache) retrieved from cache!
(ch-cache) end
EOF
pass;
