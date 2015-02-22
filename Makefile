OBJ = satelite.o ipscan.o portscan.o util.o list.o response.o webgate.o strings.o
FLAGS = -lcidr -lpthread -ljansson -g -Wall

all: scanner
scanner: $(OBJ)
	gcc $(FLAGS) $(OBJ) -o scan

satelite.o: scan.c head.h
	gcc -c $(FLAGS) -o satelite.o scan.c

ipscan.o: ipscan.c ipscan.h head.h
	gcc -c $(FLAGS) -o ipscan.o ipscan.c

portscan.o: portscan.c portscan.h head.h
	gcc -c $(FLAGS) -o portscan.o portscan.c
	
response.o: response.c response.h head.h list.h
	gcc -c $(FLAGS) -o response.o response.c

util.o: util.c util.h head.h
	gcc -c $(FLAGS) -o util.o util.c

list.o: list.c list.h
	gcc -c $(FLAGS) -o list.o list.c

webgate.o: webgate.c webgate.h strings.c
	gcc -c $(FLAGS) -o webgate.o webgate.c

strings.o: strings.c strings.h
	gcc -c $(FLAGS) -o strings.o strings.c

.PHONY=clean
clean:
	for o in [ $(OBJ) scan ]; do if [ -e $$o ]; then rm $$o; fi; done
