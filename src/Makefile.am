bin_PROGRAMS = ksb

install-exec-hook:
	echo $(bin_PROGRAMS) | xargs -I{} chown root. $(bindir)/{}
	echo $(bin_PROGRAMS) | xargs -I{} chmod u+s   $(bindir)/{}
