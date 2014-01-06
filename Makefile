PKGDIR = ../pkg/usr/
BIN = $(PKGDIR)/bin/
LIB = $(PKGDIR)/lib/
INC = $(PKGDIR)/include/tinyscheme/
DOC = $(PKGDIR)/share/tinyscheme/

all:ts tsx

ts:
	@cd src; make

tsx:
	@cd src/tsx; make

install:ts tsx
	@mkdir -p $(BIN); cp bin/tinyscheme $(BIN)
	@mkdir -p $(INC); cp src/*h src/tsx/*h $(INC)
	@mkdir -p $(DOC); cp -a doc $(DOC)
	@mkdir -p $(LIB)/tinyscheme; cp src/lib* $(LIB)
	@cp scm/* $(LIB)/tinyscheme

clean:
	@cd src; make clean
	@cd src/tsx; make clean
