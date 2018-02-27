TARGET = httpc.so
OBJS = httpc.o

CFLAGS= -Wall -Wformat -fPIC
PREFIX?=/usr/local

LDFLAGS=-L${PREFIX}/lib
LIBS=-luv -pthread 

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

all: $(TARGET)
	cp $(TARGET) ../$(TARGET)
	@echo Build complete for Igropyr

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -shared -o $(TARGET) $(LIBS)

clean:
	rm -rf $(TARGET) $(OBJS)
