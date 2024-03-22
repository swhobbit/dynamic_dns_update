.PHONY:	\
	default	\
	install	\
	lint	\
	noservice	\
	service	\
	status	\
	user

US=dns_update
US_PY=${US}.py
US_SERVICE=${US}.service

COLUMNS=$(shell tput cols)
USER=dynupdte

/etc/systemd/system/%.service: scripts/%.service
	[ -w $(dir $@ ) ]
	cp $< $@

/usr/local/sbin/%.py: %.py
	[ -w $(dir $@ ) ]
	cp $^ $@

default:
	@echo default target not supported.
	@echo Consider targets install, readme, lint, service
	exit 44

install: /usr/local/sbin/${US_PY} service

service: user service_script
	[ -w / ]
	systemctl daemon-reload
	systemctl restart ${US_SERVICE}
	systemctl enable ${US_SERVICE}
	systemctl status ${US_SERVICE}

noservice:
	[ -w / ]
	systemctl stop ${US_SERVICE}
	systemctl disable ${US_SERVICE}
	systemctl status ${US_SERVICE}

status:
	systemctl status dns_update.service


service_script: /etc/systemd/system/dns_update.service

user: ${USER}

${USER}:
	id $@ || adduser --system --group $@

README.txt: $(US_PY)
	stty cols 80
	pydoc3 ./$^ > $@
	stty cols $(COLUMNS)

lint:
	pylint ${US_PY}

