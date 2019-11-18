MAIN=dns_update.py

default:
	@echo default target not supported.
	exit 44

doc: README.txt

README.txt: $(MAIN)
	stty cols 80
	pydoc3 ./$^ > $@
	reset

install: /usr/local/sbin/${MAIN}

/usr/local/sbin/${MAIN}: ${MAIN}
	cp $^ $@

lint:
	pylint3 ${MAIN}
