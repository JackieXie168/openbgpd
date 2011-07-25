# $hrs: openbgpd/Makefile,v 1.2 2009/06/30 07:07:55 hrs Exp $

SUBDIR=	bgpd bgpctl

all: $(SUBDIR)
	set -e ; \
	for subdir in $(SUBDIR); do \
		make -C $$subdir; \
	done

clean: $(SUBDIR)
	set -e ; \
	for subdir in $(SUBDIR); do \
		make -C $$subdir clean; \
	done

distclean: $(SUBDIR)
	set -e ; \
	for subdir in $(SUBDIR); do \
		make -C $$subdir distclean; \
	done

.PHONY: all clean distclean
