# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(priority-donate-multiple3) begin
(priority-donate-multiple3) First thread should have priority 32.  Actual priority: 32.
(priority-donate-multiple3) Second thread should have priority 33.  Actual priority: 33.
(priority-donate-multiple3) Third thread should have priority 34.  Actual priority: 34.
(priority-donate-multiple3) Thread one acquired lock a.
(priority-donate-multiple3) Thread one finished.
(priority-donate-multiple3) Thread three acquired lock a.
(priority-donate-multiple3) Thread three finished.
(priority-donate-multiple3) Thread two sema down on semaphore b.
(priority-donate-multiple3) Thread two finished.
(priority-donate-multiple3) Threads one, three, two should have just finished, in that order.
(priority-donate-multiple3) end
EOF
pass;
