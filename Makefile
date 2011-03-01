NAME	:= munksgaard-egeberg-g4

all:
	make -C rapport
	make -C buenos real-clean
	mkdir $(NAME)
	cp rapport/rapport.pdf $(NAME)/$(NAME).pdf
	cp -r buenos $(NAME)
	tar czf $(NAME).tar.gz $(NAME)
	rm -rf $(NAME)

clean:
	rm -rf $(NAME).tar.gz

clean-all:
	rm -rf $(NAME).tar.gz
	rm -rf $(NAME)
	make -C rapport clean
	make -C buenos real-clean

