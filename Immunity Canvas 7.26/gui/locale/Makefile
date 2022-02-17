glade_files=$(shell find .. -name '*.glade' -or -name '*.glade2')
py_files=$(shell find .. -name '*.py')

appname=CANVAS

PO_DIR=po

pot=$(PO_DIR)/$(appname).pot
#pot_py=$(PO_DIR)/$(appname)_py.pot

MO_FILES=$(patsubst %,%/LC_MESSAGES/$(appname).mo,$(lang))

#lang=en_US
lang=ja


all:	$(MO_FILES)

clean:
	$(RM) $(MO_FILES)

$(pot):	$(glade_files) $(py_files)
	xgettext -j -d $(appname) -o $(pot) $(glade_files)
	xgettext -Lpython -kN_ -j -d $(appname) -o $(pot) $(py_files)

%.po:	$(pot)
	msgmerge -U $@ $^

%/LC_MESSAGES/$(appname).mo:	$(PO_DIR)/%.po
	@mkdir -p $(dir $@)
	msgfmt -o $@ $^
