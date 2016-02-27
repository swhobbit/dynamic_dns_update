all:
	echo target not supported

install: /usr/local/sbin/dns_update.py 


/usr/local/sbin/dns_update.py: dns_update.py
	cp $^ $@
