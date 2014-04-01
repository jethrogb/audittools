auditps
=======

An interpreter for process execution events in Linux auditd logs. It prints
exec, clone, fork, and exit syscalls in a tree-like format with timestamps,
user, group and process information.

Compatibility
=============

Tested with Ruby 1.8.7 and up.

auditd Configuration
====================

Use with following audit.rules:

	-a always,exit -F arch=b64 -S execve -S vfork -S fork -S clone -S exit -S exit_group
	-a always,exit -F arch=b32 -S execve -S vfork -S fork -S clone -S exit -S exit_group

Sample Output
=============

Output of `sudo ausearch -ts 15:11 -r|./auditps.rb|less -S`:

	TIME        USERS         GROUPS        TTY      PROCESS
	                                                 \_ 7639
	                                                  \_ 9081
	Apr01 15:11 jethro        jethro        pts3        | CLONE : -> 18487 bash
	                                                    \_ 18487
	Apr01 15:11 jethro,root   jethro        pts3        | | EXECVE: sudo ausearch -ts 15:11 -r
	Apr01 15:11 root          jethro        pts3        | | CLONE : -> 18491 sudo
	                                                    | \_ 18491
	Apr01 15:11 root          root          pts3        |     EXECVE: ausearch -ts 15:11 -r
	Apr01 15:11 root          root          pts3        |     EXITGR: ausearch
	Apr01 15:11 root          jethro        pts3        |   EXITGR: sudo
	Apr01 15:11 jethro        jethro        pts3        | CLONE : -> 18488 bash
	                                                    \_ 18488
	Apr01 15:11 jethro        jethro        pts3        | | EXECVE: /usr/bin/env ruby ./auditps.rb
	Apr01 15:11 jethro        jethro        pts3        | | EXECVE: ruby ./auditps.rb
	Apr01 15:11 jethro        jethro        pts3        | | CLONE : -> 18490 ruby
	                                                    | \_ 18490
	Apr01 15:11 jethro        jethro        pts3        |     EXIT  : ruby
	Apr01 15:11 jethro        jethro        pts3        |   EXITGR: ruby
	Apr01 15:11 jethro        jethro        pts3        | CLONE : -> 18489 bash
	                                                    \_ 18489
	Apr01 15:11 jethro        jethro        pts3            EXECVE: less -S
	Apr01 15:12 jethro        jethro        pts3            EXITGR: less
