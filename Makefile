MAIN=dns_update.py

all:
	echo target not supported

install: /usr/local/sbin/${MAIN}

/usr/local/sbin/${MAIN}: ${MAIN}
	cp $^ $@

lint:
	pylint ${MAIN}
