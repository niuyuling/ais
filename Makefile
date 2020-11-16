CROSS_COMPILE ?= 
CC := $(CROSS_COMPILE)gcc
STRIP := $(CROSS_COMPILE)strip
CFLAGS += -g -O2 -Wall
LIBS = 
OBJ := ais

all: ais.o conf.o
	$(CC) $(CFLAGS) -o $(OBJ) $^ $(LIBS)
.c.o:
	$(CC) $(CFLAGS) -c $< $(LIBS)

clean:
	rm -rf *.o
	rm $(OBJ)

