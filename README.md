# kld-rootkit
## A collection of FreeBSD rootkit kernel modules and utilities

**TL;DR ./install_rootkit.sh -s**


This rootkit was developed and tested on FreeBSD 13.0-RELEASE. It is a
collection of kernel modules and utilities derived from the examples in
Joseph Kong's excellent book [DESIGNING BSD ROOTKITS](https://nostarch.com/rootkits.htm), which I highly encourage
anyone with interest in kernel programming to read.

This rootkit provides functionality for process hiding, file hiding, kernel
module hiding, file redirection, on-demand privilege escalation, backdoor
capability, and persistence.

The following is a list and brief descriptions of the kernel modules contained
in this rootkit:

- **shdw_sysent_tbl**  - Lookup table stored in kernel space which contains a
                      mapping of system call numbers and functions that have
                      been hooked. Used to assist with altering and restoring
                      the real sysent table.

- **shdw_lookup**      - System call to look up syscall numbers in the shadow
                      sysent table. Used to find the syscall numbers that
                      are part of the rootkit.

- **deepbg**           - System call to hide a running process and it's children.

- **stash**            - getdirentries system call hook. Used to hide files
                      that have a magic string in their filename.

- **knighted**         - System call to give the calling process root privileges.

- **whisper**          - System call to hide an open TCP connection.

- **file_redirection** - open system call hook. Used to open a file with a magic
                      string extension, if it exists, in place of the given
                      filename.

- **order_66**         - A backdoor icmp_input hook that is triggered whenever a
                      specially crafted ICMP packet is received.

- **kmalloc**          - Technically, not part of the rootkit. It is compiled to
                      produce byte code for allocating kernel memory and to
                      demonstrate the run-time kernel memory patching
                      technique from the book.

##
Below are a list and brief descriptions of user space tools included in the
rootkit:

- **interface-lookup**  - Look up syscall numbers associated with the rootkit's
                       capabilities.

- **knight-me**         - Uses the knighted system call to drop the user into a
                       rootshell.

- **interface-whisper** - Uses the whisper system call to hide an open TCP
                       connection.

- **loader**            - Works in conjunction with stash and file_redirection to
                       replace a file with a trojan without altering the file's
                       access and modification times.

- **trigger**           - Used with the order_66 backdoor and a listener like
                       netcat (nc) to make a reverse shell connection.
##
The following are demonstration programs which are not part of the core rootkit,
but were included as examples of various other techniques from the book:

- **interface-kmalloc**  - User space program that demonstrates using modfind to
                        locate the kmalloc syscall and then invokes it allocate
                        kernel memory.

- **kvm-write**          - User space program that demonstrates using kvm (kernel
                        memory interface) to write to kernel memory.

- **test-kmalloc-patch** - User space program which demonstrates run-time kernel
                        memory patching to allocate kernel memory.


## How to Install

If kernel sources are in a non-standard location (i.e. other than /usr/src/sys)
set the SYSDIR environment variable to the location of the "sys" directory in
your kernel source tree.

Run the "install_rootkit.sh" script as root.

Use the "-s" option to install in stealth mode which will avoid printing debug
messages to the system log and will employ the kernel module hiding and
persistence capabilities.

Running the script without the "-s" option will basically install the rootkit
in test mode. Debug messages will be written to the console and system log.
No attempt to hide the kernel modules or achieve persistence will be made.

An optional argument for the "magic word" can be used as well. This string
is used as a password to activate some features in this rootkit such as the
order_66 backdoor and knighted rootshell. This string can also be used as
part of a file's name to use the file hiding and redirection capabilities.

The default magic word is "z4xX0n".
