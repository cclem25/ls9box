SRCDIR=.
DESTDIR=

ID=ls9box
VERSION=`cat $(SRCDIR)/VERSION`
LICENSE=GPL

BINDIR=$(DESTDIR)/usr/bin
LIBDIR=$(DESTDIR)/usr/share/$(ID)
MANDIR=$(DESTDIR)/usr/share/man/man1
SANDBOXDIR=sandbox

PACKAGE=$(ID)-$(VERSION)
PACKAGEDIR=$(SANDBOXDIR)/$(PACKAGE)
CURRENTDIR=`pwd`
EXEC=install


all: $(EXEC)

reinstall: uninstall install

install: build_docs
	@echo "----- Installation de $(ID)..."
	install -d -m 0755 -o root -g root $(BINDIR)
	install -d -m 0755 -o root -g root $(LIBDIR)
	install -d -m 0755 -o root -g root $(MANDIR)
	install    -m 0755 -o root -g root $(SRCDIR)/$(ID).py $(LIBDIR)
	install    -m 0644 -o root -g root $(SRCDIR)/NeufBox.py $(LIBDIR)
	install    -m 0755 -o root -g root $(SRCDIR)/docs/$(ID).1.gz $(MANDIR)
	@echo "----- Installation terminée."
	
uninstall:
	@echo "----- Suppression de $(ID)..."
	rm -Rf $(LIBDIR)
	rm -f $(BINDIR)/$(ID)
	@echo "----- Terminée."

package: clean_package build_docs
	@mkdir -p $(PACKAGEDIR)
	@cp $(SRCDIR)/*.py $(PACKAGEDIR)/
	@cp $(SRCDIR)/VERSION $(PACKAGEDIR)/
	@cp $(SRCDIR)/Makefile $(PACKAGEDIR)/
	@cp -R $(SRCDIR)/docs $(PACKAGEDIR)/
	@tar czf $(PACKAGE).tar.gz -C $(SANDBOXDIR) --exclude=.svn $(PACKAGE)
	@mv $(PACKAGE).tar.gz $(SANDBOXDIR)

clean_package:
	@rm -Rf $(PACKAGEDIR)
	
clean_sandbox:
	@rm -Rf $(SANDBOXDIR)/*
	
clean_docs:
	@rm -f $(SRCDIR)/docs/*.gz
	
clean:
	@rm -f $(SRCDIR)/*.py[co]

build_docs: clean_docs
	@gzip -c $(SRCDIR)/docs/$(ID).1 >$(SRCDIR)/docs/$(ID).1.gz
