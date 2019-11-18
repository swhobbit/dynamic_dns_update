MAIN=dns_update.py
COLUMNS=$(shell tput cols)

default:
	@echo default target not supported.
	exit 44

install: /usr/local/sbin/${MAIN}

README.txt: $(MAIN)
	stty cols 80
	pydoc3 ./$^ > $@
	stty cols $(COLUMNS)

/usr/local/sbin/${MAIN}: ${MAIN}
	cp $^ $@

lint:
	pylint3 ${MAIN}
