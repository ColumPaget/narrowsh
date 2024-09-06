narrowsh - another restricted shell
-----------------------------------

narrowsh is a very, VERY, basic shell created to handle situations where an untrusted party, and particularly an automated process, is given access to a system via telnet, ssh or the like. By default it will only accept commands using the '-c' shell option (which is how ssh runs commands), however it can be configured to read commands line-by-line from stdin. It was specifically created for use with ppp-over-ssh vpns that launch pppd via ssh's "-c" command-line-option, but shouldn't allow any other commands to be run from ssh. It is expected to be configured by an administrator/superuser (usually 'root') and therefore expects configuration files to be in /etc/narrowsh/ and nowhere else. Further it will not run commands if those configuration files are world-writable, or if they are owned by the user that is trying to run narrowsh.

narrowsh is very basic, and so far supports no shell features like setting environment variables, creating pipelines of commands, or variable subsitution. It exists purely as a means to allow remote entities to run selected commands, and only those commands, on a system. 

narrowsh can be configured on a user-by-user basis to only allow certain commands to be run, and on both a user and command basis it can apply a number of security limits or features to the session. 

These features and limits are:

  * Disable use of shell primatives that allow running other processes: The characters ;`|& are blanked out in all shell commands.
  * Disable 'su', 'sudo' or priviledge escalation by 'suid' methods (prctrl(PR_NO_NEW_PRIVS)).
  * No access to network (using 'unshare' to disconnect from network namespace)
  * No access to IPC (using 'unshare' to disconnect from IPC namespace)
  * 'fake' hostname support (using UTC namespace)
  * Configurable inactivity timeout
  * Secondary Challenge-Response authentication support
  * Google-authenticator compatible OTP support
  * Attempt to prevent further execs by using resource limits to block fork()
  * Basic menu system


unfortunately some of thesee features, those that use namespaces or the 'disable suid' feature, are linux specific.



USAGE
-----

The config files override any settings on the command-line. Thus security options can be turned on via the command-line, but cannot be turned off if they are on in the config-file.



THE USUAL CAVEATS
=================

Restricted shells suffer from one significant failing: if access is granted to any application that allows the user to launch other applications, then their security is undermined. There's a number of methods that could be used to fix this, but in the initial release of narrowsh the only one used is the 'user maximum processes' resource limit. If narrowsh is run with '-X' or 'noexec' options, then just before an application is run, the number of processes rlimit (RLIMIT_NPROC) is set to '1'. This doesn't prevent execs, but it does prevent forks, and normally commands that can launch other programs don't replace themselves with those other programs, but fork first and then the child process switches to the desired program using exec. Thus preventing fork should prevent running further programs, and has been seen to do so. However, there may be ways to get around this methodology.

In future it is expected that other methods will be added to combat 'launching an app from an app'.



USAGE
=====

```
    narrowsh
    narrowsh <options> <command line>
```

without any arguments narrowsh tries to open /etc/narrowsh/<username>.conf and read settings from that


OPTIONS 
=======

```
  -c <command line>  command-line to run, as in ´/bin/sh -c <command>´
  -i                 force interactive mode (otherwise must be set in config file>
  -m                 force menu mode (otherwise must be set in config file>
  -S                 disallow use of su/sudo/suid
  -X                 disallow running further child programs (attempts to block 'fork()')
  -N                 create a namespace with no network access
  -I                 create a namespace with no Inter Process Communication access
  -P                 create a namespace with no ability to see other processes running on the system
  -n <value>         run with process priority (´nice´) of <value>
  -T <value>         inactivity timeout after ´value´ secs. Suffixes of ´m´ ´h´ can be used for minutes and hours
  -F <value>         maximum numbers of files that can be opened
  -M <value>         max memory use in bytes. Supports suffixes ´k´, ´M´ and ´G´ for kilo, mega and giga
  -?                 print this help
  -help              print this help
  --help             print this help
```


CONFIG FILE
===========

By default narrowsh looks in `/etc/narrowsh` for a file `<username>.conf` where `<username>` is the name of the current user that's running narrowsh. Entries in config file are a single line consisting of a full path to a command followed by options that are either a single word, or a name=value pair. 

A special name 'narrowsh', that is not a full path, is used to set global options for all commands, or to set 'interactive' or 'menu' mode.

A special name 'exit' provides an option that will exit from a menu.

N.B. narrowsh will not use a config file that is world or group readable or writable, or that is owned by the authenticating user. It expects the config-file to be managed and owned by root, or at least some other user.


CONFIG FILE OPTIONS
===================

```
  interactive        read commands from std-in like a normal shell (can only be set against 'narrowsh')
  menu               display a menu of commands to choose from (can only be set against 'narrowsh')
  once               only allow picking one option from the menu, and exit when that is finished running (can only be set against 'narrowsh')
  banner=<string>    up to 3 lines of banner message to display at the top of the menu (can only be set against 'narrowsh')
  title=<string>     title of process to display in menu
  nosu               prevent any user change via su/sudo/suid
  hostname=<string>  use namespaces to 'fake' the hostname of the system 
  nonet              use namespaces to disable network access
  noipc              use namespaces to disable IPC access
  noexec             prevent the launched process from itself spawning further execuatables (currently works by blocking fork)
  nice=<value>       set processor usage level ('nice') to <value>
  timeout=<value>    disconnect if idle for 'value' seconds
  procs=<value>      maximum number of processes for this user
  files=<value>      maximum number of open files
  fsize=<value>      maximum size writable to a file (accepts a k, M, G suffix for kilo, Mega, Giga)
  mem=<value>        maximum memory usage (accepts a k, M, G suffix for kilo, Mega, Giga)
  totp=<key>         google-authenticator-compatible authentication using 'key'
  otp=<key>          google-authenticator-compatible authentication using 'key'
  challenge=<key>    challenge-response authentication using key/password 'key'
  cmd=<string>       real command to run, where the normal 'path' to the command is an identifier instead
  args=<string>      force arguments of command
  sha256=<hash>      provide a hexidecimal hash. Executable will not be run if it doesn't match this
```

If the 'args' option is used, then the user must enter a command-line that matches exactly. If it is not used, and there is a matching command that doesn't have the 'args' option, then the user will be able to provide their own arguments to the command.

The 'noexec' option should prevent launching other commands from e.g. vim, but may upset programs that run subprocesses as part of their normal behavior. In that case it may be possible to use the procs option to limit the number of processes more precisely.


EXAMPLE CONFIG FILES
====================

```
    narrowsh interactive files=20 mem=10M
    /usr/sbin/ppp
    /usr/bin/vi nosu nonet noipc totp=XF943Z2140XPJMMRQ6V99
		/usr/bin/vi args=/etc/hosts
```

The above config sets global rules that all applications cannot see other apps vi proc or ps, and can have a maxiumum of 20 files open and use up to 10 meg of ram. The 'interactive' keyword specifies that narrowsh will allow commands to be typed in, as well as entered using '-c'. The applications 'ppp' and 'vi' can be run. 'vi' has extra restrictions of 'no switching of user' and 'no network or ipc visiblity' and on attempting the run the 'vi' the user will be asked to authenticate using google-authenticator style OTP.

Alternatively


```
    narrowsh menu totp=XF943Z2140XPJMMRQ6V99 banner="choose from the follwing options"
    /usr/sbin/ppp files=20 mem=10M title="ppp vpn"
    /usr/bin/vi nosu nonet noipc noexec title="vi editor"
    exit
 ```

Will ask the user to authenticate using google-authenticator style OTP before doing anything else. If Authentication passes then a menu of commands is offered to the user, with a banner telling them to chose one. They can choose from "ppp vpn" or "vi editor", which are the titles displayed in the menu, or 'exit' which exits the menu. Now 'ppp' is limited on files and memory. 'vi' is not permitted to su/sudo nor fork subprocesses, but ppp is because it needs both these features to function.



CHALLENGE_RESPONSE AUTHENTICATION
=================================

narrowsh supports challenge-response authentication using the 'challenge' config-file option. This is intended to add some security to unencrypted links like telnet or rsh that send passwords in the clear. narrowsh sends a 'challenge' string, to which the password must be appended, and then the whole thing SHA1 hashed and the result entered into narrowsh. 

The 'challenge' config-file option has the format 'challenge=<key>' where 'key' is a secret password or passphrase that is known to the authenticting user. This key is stored in the config-file in plain text, thus the config-file should not be world-readable.



TOTP AUTHENTICATION
===================

narrowsh supports google-authenticator compatible TOTP authentication. This is set with the `totp=<key>` command-line option, where 'key' is a secret password (usually a long string of random characters) known to both parties. This key is stored in the config-file in plain text, thus the config-file should not be world-readable.



SHA256 FILE CHECKS
==================

For the excessively paranoid, the 'sha256' option allows booking a hexadecimal hash value against a command. If this option is supplied, the command executable will be sha256 hashed to see that it matches the expected value, and will not be run if it doesn't.



NAMESPACES
==========

The 'nonet', 'noipc', 'nopid' and 'hostname' options all use linux namespaces. These features are still somewhat experimental can be left out at compile time, so a given narrowsh instance may not support them.
