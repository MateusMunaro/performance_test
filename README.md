Para instalar o compilador em um hambiente Ubunto:

Para instalar pacotes: 

sudo apt-get install libpcap-dev

Para compilar o projeto:

gcc -o ddos_detector ddos_detector.c -lpcap -lpthread

Após compilar o projeto, basta executar este comando: 

gcc -o ddos_detector ddos_detector.c -lpcap -lpthread
