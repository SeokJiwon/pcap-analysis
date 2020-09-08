all: pcap-analysis

pcap-analysis: main.o
	g++ -o pcap-analysis  main.o -lpcap

main.o: main.cpp 
	g++ -c -o main.o main.cpp 

clean: 
	rm -f pcap-analysis *.o
