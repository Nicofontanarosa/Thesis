import sys
import main

def run():
    
    if len(sys.argv) != 5:
        print(f"Usage: {sys.argv[0]} <pcap> <ndpi> <output> <protoname>")
        sys.exit(1)

    pcap = sys.argv[1]
    ndpi = sys.argv[2]
    output = sys.argv[3]
    protoname = sys.argv[4].capitalize()

    main.main_pipeline(pcap, ndpi, output, protoname)

if __name__ == "__main__":
    run()
