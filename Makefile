NAME	:= munksgaard-egeberg-g4

all: 	clean-all rapport
	mkdir $(NAME)
	cp rapport/rapport.pdf $(NAME)/$(NAME).pdf
	cp -r buenos $(NAME)
	rm -v $(NAME)/buenos/fyams.harddisk $(NAME)/buenos/fyams.socket
	tar czf $(NAME).tar.gz $(NAME)
	rm -rf $(NAME)

buenos:
	make -C buenos

rapport:
	make -C rapport

clean:
	rm -rf $(NAME).tar.gz

clean-all:
	rm -rf $(NAME).tar.gz
	rm -rf $(NAME)
	make -C rapport clean
	make -C buenos real-clean
	make -C buenos/tests clean

.PHONY: rapport
