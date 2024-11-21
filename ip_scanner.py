import nmap
scanner = nmap.PortScanner()
ip = input("Inserte una direccion IP")
scanner.scan(ip)
print(scanner.all_hosts())