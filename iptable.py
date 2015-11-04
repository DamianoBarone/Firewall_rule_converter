#IPTABLE, per il protocollo se tcp mettere 0 se udp mettere 1
#Per mettere un range di valori utilizzare il carattere '-' , ad esempio se una regola accetta protocolli sia tcp che udp si deve inserire 0-1 . Inoltre va messa l'azione della regola prima della regola stessa, si posso raggruppare le regole che hanno la stessa azione. I campi disponibili sono protocol, srcport, srcip, destport, destip. Si devono specificare tutti i campi. Inoltre tra una parola e l'altra deve esserci uno spazio.
#ACCEPT
#protocol = 1-1 srcport = 500-600  srcip = 4002-5001 destport = 5001-6000 destip = 2002-2002
ACCEPT
protocol = 1-1 srcport = 500-600  srcip = 192.169.1.1-192.170.1.1 destport = 5001-6000 destip = 192.168.1.1-192.168.1.1
protocol = 0-0 srcport = 201-400  srcip = 192.180.1.1-192.190.1.1 destport = 2000-2000 destip = 200.168.1.1-250.168.1.1
protocol = 0-0 srcport = 0-200    srcip = 200.168.1.1-200.238.1.1 destport = 2500-5000 destip = 129.168.1.1-130.168.1.1
protocol = 1-1 srcport = 601-700  srcip = 255.168.1.1-255.168.1.1 destport = 6500-7000 destip = 255.168.1.1-255.168.1.1

REJECT
protocol = 1-1 srcport = 701-802  srcip = 100.168.1.1-120.168.1.1 destport = 7500-8000 destip = 200.168.1.1-220.168.1.1
protocol = 0-0 srcport = 801-4000  srcip = 250.168.1.1-250.168.1.1 destport = 8500-9000 destip = 120.168.1.1-130.168.1.1

DEFAULT = ACCEPT