bin_PROGRAMS = ksb
data_DATA = debian.img
CLEANFILES = debian.img

debian.img:
	mkdir -p debian
	truncate -s 1G debian.img
	mkfs.ext4 debian.img
	sudo mount debian.img debian
	sudo cdebootstrap `lsb_release -cs` debian http://deb.debian.org/debian
	sudo umount debian
	rmdir debian
	fallocate -d debian.img

install-exec-hook:
	echo $(bin_PROGRAMS) | xargs -I{} chown root. $(bindir)/{}
	echo $(bin_PROGRAMS) | xargs -I{} chmod u+s   $(bindir)/{}
