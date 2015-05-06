CC=gcc
LDFLAG=-lcunit -lpcap
CFLAG=-Wall -g -std=gnu99 -I../src
EXEC=unitTests

all: $(EXEC)

$(EXEC): main.o test_config.o ../src/config.o 
	@$(CC) -o $@ $^ $(LDFLAG)

%.o: %.c
	@$(CC) -o $@ -c $< $(CFLAG)


.PHONY: test clean mrproper

test: all
	@./$(EXEC)

clean:
	@rm -f *.o

mrproper: clean
	@rm -f $(EXEC)

