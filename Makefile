MAIN=dns_update.py

default:
	@echo default target not supported.
	exit 44

doc: README.txt

install: /usr/local/sbin/${MAIN}

README.txt: $(MAIN)
	stty cols 80
	pydoc3 ./$^ > $@
	reset

/usr/local/sbin/${MAIN}: ${MAIN}
	cp $^ $@

lint:
	pylint3 ${MAIN}
