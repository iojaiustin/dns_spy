# dns_spy
Simple dns sniffer writen in python

# LINUX USAGE

1. Run mitm.py
    1.1 You will be prompted, each by each, three input fields:
        1.1.1 Your interface. Type ```ifconfig``` in your terminal. You will most
                probably have two interfaces, your *lo*, which is your loopback interface
                and your actual network card interface with your local ip. Mine was
                192.168.<something>.<something>
        1.1.2 Victim's IP. Here come other tools in hand, but I tested it on my computer.
              If you want to do so, then in the same block of text as the interface, you
                will have your local IP.
        1.1.3 Router's IP. Can be found via a one-liner in the terminal, that is
                ```route -n | grep 'UG[ \t]' | awk '{print $2}'```
   2. Run dns_sniff.py
    2.1 You will be prompted to an input field. This will be your interface card.
        It will be the same as in 1.1.1
3. Listen.
    3.1 A confirmation prompt will be shown ( [!] Listening... ). Do your thing from
        now onwards.
