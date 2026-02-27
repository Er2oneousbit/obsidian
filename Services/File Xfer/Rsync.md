#rsync #remotesync

- [Rsync](https://linux.die.net/man/1/rsync) is a fast and efficient tool for locally and remotely copying files. It can be used to copy files locally on a given machine and to/from remote hosts.
- Port 873, can use SSH
	- [How to Transfer Files with Rsync over SSH {With Examples} (phoenixnap.com)](https://phoenixnap.com/kb/how-to-rsync-over-ssh)
- Abuse tricks https://book.hacktricks.xyz/network-services-pentesting/873-pentesting-rsync
- Nmap scripts
- Connect with [[Netcat]]
- Connect with rsync client `rsync -av --list-only rsync://127.0.0.1/dev`
- Look for things to use like ssh keys