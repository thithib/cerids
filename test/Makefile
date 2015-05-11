CC=gcc
LDFLAG=-lcunit -lpcap
CFLAG=-Wall -g -std=gnu99 -I../src/include
EXEC=unitTests

all: cerids $(EXEC)

$(EXEC): main.o test_config.o test_sniffer.o ../src/config.o ../src/sniffer.o ../src/parser.o
	@$(CC) -o $@ $^ $(LDFLAG)

%.o: %.c
	@$(CC) -o $@ -c $< $(CFLAG)


.PHONY: cerids test clean mrproper

cerids:
	@cd ../src ; make ; cd ../test

test: all
	@./$(EXEC)

clean:
	@rm -f *.o

mrproper: clean
	@rm -f $(EXEC) ; cd ../src ; make mrproper ; cd ../test

