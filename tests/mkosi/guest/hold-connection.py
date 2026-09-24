# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: GPL-2.0-or-later

"""Connect to the defused socket and hold the connection open.

Accept=yes starts one service instance per connection, so this keeps an
instance alive for as long as the test needs to look at it.
"""

import socket
import sys
import time

s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
s.connect(sys.argv[1])
time.sleep(120)
