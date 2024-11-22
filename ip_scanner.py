import nmap

scanner = nmap.PortScanner()
ip = input("Inserte una direccion IP: ")
tipo_escaneo = input("Tipo de escaneo (ej: -sS, -sT, -sV, o dejar vacío para un escaneo TCP completo): ") # Permite especificar tipo de escaneo
puerto_inicio = input("Puerto de inicio (ej: 20 o dejar vacío para un escaneo completo): ")
puerto_fin = input("Puerto de fin (ej: 1024 o dejar vacío para un escaneo completo): ")


scan_args = ""

if tipo_escaneo != "":
    scan_args += f" {tipo_escaneo}"

if puerto_inicio != "" and puerto_fin != "":
    scan_args += f" -p {puerto_inicio}-{puerto_fin}"
elif puerto_inicio != "":
    scan_args += f" -p {puerto_inicio}"

scanner.scan(ip, arguments=scan_args)

print(scanner.all_hosts())

for host in scanner.all_hosts():
    print('----------------------------------------------------')
    print('Host : %s (%s)' % (host, scanner[host].hostname()))
    print('State : %s' % scanner[host].state())
    for proto in scanner[host].all_protocols():
        print('----------')
        print('Protocol : %s' % proto)
        lport = scanner[host][proto].keys()
        sorted(lport)
        for port in lport:
            print ('port : %s\tstate : %s' % (port, scanner[host][proto][port]['state']))
