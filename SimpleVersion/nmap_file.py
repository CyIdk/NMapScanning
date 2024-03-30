import nmap

class NmapScan:

    """NMScan class to perform nmap scans on a target ports"""
    def __init__(self,target):

        # NOTE: Create an object of the nmap.PortScanner() class
        self.nm = nmap.PortScanner()

        # Set the target to the target ip or hostname
        self.target = target


    def perform_nmap_scan(self):

        # NOTE - Perform a basic scan on the target using the scan() method
        # - target is the ip or hostname of wensite
        # - ports is number of ports to scan
        # - argument is the scan type here we are using TCP scan
        self.nm.scan(self.target, ports='1-1000',arguments='sT')  

        # Print scan results
        print("\n--------------------------------------------------------------")
        print(f"Nmap port scan TCP on:\n{self.target}")

        ## printing the host or ip of the 
        for host in self.nm.all_hosts():
            print(f"\nHost: {host}")

            ## printing the state of the target server
            print(f"State: {self.nm[host].state()}")
            
            ## loop thru all the ports 
            for proto in self.nm[host].all_protocols():
                ###print the protocol we are using
                print(f"Protocol: {proto}")

                ## Use the keys to loop thru the results
                ports = self.nm[host][proto].keys()
                for port in ports:
                    ##print the port info
                    print(f"Port: {port} - State: {self.nm[host][proto][port]['state']}")

        # Print CSV raw scan output
        print("\n--------------------------------------------------------------")
        print("Nmap Scan CSV Output:")

        # NOTE: Print the raw scan output in CSV format
        print(self.nm.csv())

# create an object of the NmapScan class
nmap_scan_object = NmapScan('https://scanme.nmap.org')
nmap_scan_object.perform_nmap_scan()