/*
 * DDoS Detection and Mitigation System
 * Um sistema robusto para capturar, analisar e mitigar ataques DDoS em tempo real
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <pcap.h>
#include <pthread.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdarg.h>

/* Definições e constantes */
#define PACKET_BUFFER_SIZE 65536
#define MAX_BLOCKLIST_SIZE 10000
#define MAX_STATS_ENTRIES 10000
#define EXPIRATION_TIME 3600     // 1 hora em segundos
#define THRESHOLD_WINDOW 10      // Janela de tempo em segundos
#define PACKET_THRESHOLD 1000    // Limite de pacotes por janela de tempo
#define SYN_THRESHOLD 500        // Limite de pacotes SYN por janela de tempo
#define ICMP_THRESHOLD 200       // Limite de pacotes ICMP por janela de tempo
#define UDP_THRESHOLD 800        // Limite de pacotes UDP por janela de tempo
#define MAX_HOST_CONNECTIONS 100 // Limite de conexões por host
#define BLOCKLIST_FILE "blocklist.dat"
#define LOG_FILE "ddos_detection.log"

/* Estruturas de dados */
typedef struct
{
    char ip[INET_ADDRSTRLEN];
    time_t timestamp;
    int count;
    int blocked;
} BlocklistEntry;

typedef struct
{
    char ip[INET_ADDRSTRLEN];
    time_t first_packet;
    int total_packets;
    int syn_packets;
    int icmp_packets;
    int udp_packets;
    int active_connections;
} TrafficStats;

/* Variáveis globais */
static pcap_t *pcap_handle;
static FILE *log_file = NULL;
static pthread_mutex_t blocklist_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;
static int running = 1;

/* Arrays para armazenar blocklist e estatísticas */
static BlocklistEntry blocklist[MAX_BLOCKLIST_SIZE];
static int blocklist_count = 0;
static TrafficStats traffic_stats[MAX_STATS_ENTRIES];
static int stats_count = 0;

/* Protótipos de funções */
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void init_blocklist();
int add_to_blocklist(const char *ip, int block_immediately);
int is_blocked(const char *ip);
void clean_blocklist();
void save_blocklist();
void load_blocklist();
void init_traffic_stats();
void update_traffic_stats(const char *ip, int is_syn, int is_icmp, int is_udp);
void detect_ddos_attacks();
void block_ip(const char *ip);
void unblock_ip(const char *ip);
void *detection_thread(void *arg);
void *maintenance_thread(void *arg);
void write_log(const char *format, ...);
void cleanup_and_exit(int signum);

int main(int argc, char *argv[])
{
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    bpf_u_int32 net, mask;
    pthread_t detect_tid, maintenance_tid;

    /* Abrir arquivo de log */
    log_file = fopen(LOG_FILE, "a");
    if (log_file == NULL)
    {
        fprintf(stderr, "Erro ao abrir arquivo de log: %s\n", strerror(errno));
        log_file = stdout; // Fallback para stdout
    }

    /* Tratar sinais para saída limpa */
    signal(SIGINT, cleanup_and_exit);
    signal(SIGTERM, cleanup_and_exit);

    /* Inicializar blocklist e estatísticas */
    init_blocklist();
    init_traffic_stats();
    load_blocklist();

    write_log("Sistema de detecção e mitigação de DDoS iniciando...\n");

    /* Determinar interface de rede */
    if (argc > 1)
    {
        dev = argv[1];
    }
    else
    {
        /* Substitui pcap_lookupdev (depreciado) por pcap_findalldevs */
        pcap_if_t *alldevs;
        if (pcap_findalldevs(&alldevs, errbuf) == -1)
        {
            write_log("Erro ao buscar interfaces: %s\n", errbuf);
            return 1;
        }

        if (alldevs == NULL)
        {
            write_log("Nenhuma interface disponível\n");
            return 1;
        }

        /* Usa a primeira interface encontrada */
        dev = strdup(alldevs->name);
        pcap_freealldevs(alldevs);

        if (dev == NULL)
        {
            write_log("Não foi possível encontrar interface padrão\n");
            return 1;
        }
    }

    write_log("Interface de rede: %s\n", dev);

    /* Obter informações da rede */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
    {
        write_log("Não foi possível obter informações da rede: %s\n", errbuf);
        net = 0;
        mask = 0;
    }

    /* Abrir a interface para captura */
    pcap_handle = pcap_open_live(dev, PACKET_BUFFER_SIZE, 1, 1000, errbuf);
    if (pcap_handle == NULL)
    {
        write_log("Não foi possível abrir a interface %s: %s\n", dev, errbuf);
        return 2;
    }

    /* Configurar filtro para capturar apenas pacotes IP */
    if (pcap_compile(pcap_handle, &fp, "ip", 0, net) == -1)
    {
        write_log("Erro ao compilar filtro: %s\n", pcap_geterr(pcap_handle));
        return 3;
    }

    if (pcap_setfilter(pcap_handle, &fp) == -1)
    {
        write_log("Erro ao aplicar filtro: %s\n", pcap_geterr(pcap_handle));
        return 4;
    }

    pcap_freecode(&fp);

    /* Iniciar threads de detecção e manutenção */
    pthread_create(&detect_tid, NULL, detection_thread, NULL);
    pthread_create(&maintenance_tid, NULL, maintenance_thread, NULL);

    write_log("Iniciando captura de pacotes...\n");

    /* Iniciar a captura de pacotes (loop) */
    pcap_loop(pcap_handle, 0, packet_handler, NULL);

    /* Aguardar finalização das threads */
    pthread_join(detect_tid, NULL);
    pthread_join(maintenance_tid, NULL);

    /* Cleanup final */
    save_blocklist();
    pcap_close(pcap_handle);
    if (log_file != stdout)
        fclose(log_file);

    return 0;
}

/* Função para manipular pacotes capturados */
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    struct ip *ip_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    struct icmphdr *icmp_header;
    char source_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];
    int is_syn = 0;
    int is_icmp = 0;
    int is_udp = 0;

    /* Ignorar cabeçalho Ethernet (14 bytes) */
    const u_char *ip_packet = packet + 14;
    ip_header = (struct ip *)ip_packet;

    /* Converter endereços IP para formato legível */
    inet_ntop(AF_INET, &(ip_header->ip_src), source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);

    /* Verificar se o IP de origem já está bloqueado */
    pthread_mutex_lock(&blocklist_mutex);
    if (is_blocked(source_ip))
    {
        pthread_mutex_unlock(&blocklist_mutex);
        return; // Ignorar pacotes de IPs bloqueados
    }
    pthread_mutex_unlock(&blocklist_mutex);

    /* Identificar o tipo de pacote baseado no protocolo */
    switch (ip_header->ip_p)
    {
    case IPPROTO_TCP:
        tcp_header = (struct tcphdr *)(ip_packet + (ip_header->ip_hl << 2));
        /* Verificar se é um pacote SYN (para detecção de SYN flood) */
        if (tcp_header->syn && !tcp_header->ack)
        {
            is_syn = 1;
        }
        break;

    case IPPROTO_UDP:
        udp_header = (struct udphdr *)(ip_packet + (ip_header->ip_hl << 2));
        is_udp = 1;
        break;

    case IPPROTO_ICMP:
        icmp_header = (struct icmphdr *)(ip_packet + (ip_header->ip_hl << 2));
        is_icmp = 1;
        break;
    }

    /* Atualizar estatísticas de tráfego */
    pthread_mutex_lock(&stats_mutex);
    update_traffic_stats(source_ip, is_syn, is_icmp, is_udp);
    pthread_mutex_unlock(&stats_mutex);
}

/* Thread para detectar ataques periodicamente */
void *detection_thread(void *arg)
{
    while (running)
    {
        pthread_mutex_lock(&stats_mutex);
        detect_ddos_attacks();
        pthread_mutex_unlock(&stats_mutex);

        /* Verificar a cada 1 segundo */
        sleep(1);
    }
    return NULL;
}

/* Thread para manutenção periódica (limpeza de listas, salvar blocklist, etc.) */
void *maintenance_thread(void *arg)
{
    while (running)
    {
        pthread_mutex_lock(&blocklist_mutex);
        clean_blocklist();
        save_blocklist();
        pthread_mutex_unlock(&blocklist_mutex);

        /* Realizar manutenção a cada 5 minutos */
        sleep(300);
    }
    return NULL;
}

/* Inicializar blocklist */
void init_blocklist()
{
    blocklist_count = 0;
    memset(blocklist, 0, sizeof(blocklist));
}

/* Adicionar IP à blocklist */
int add_to_blocklist(const char *ip, int block_immediately)
{
    time_t current_time = time(NULL);

    /* Verificar se o IP já está na blocklist */
    for (int i = 0; i < blocklist_count; i++)
    {
        if (strcmp(blocklist[i].ip, ip) == 0)
        {
            blocklist[i].count++;
            blocklist[i].timestamp = current_time;

            /* Bloquear se count exceder limite ou se solicitado */
            if (block_immediately || blocklist[i].count > 100)
            {
                if (!blocklist[i].blocked)
                {
                    blocklist[i].blocked = 1;
                    block_ip(ip);
                    write_log("IP %s bloqueado (contagem: %d)!\n", ip, blocklist[i].count);
                }
            }
            return i;
        }
    }

    /* Adicionar novo IP se houver espaço */
    if (blocklist_count < MAX_BLOCKLIST_SIZE)
    {
        strcpy(blocklist[blocklist_count].ip, ip);
        blocklist[blocklist_count].timestamp = current_time;
        blocklist[blocklist_count].count = 1;
        blocklist[blocklist_count].blocked = block_immediately;

        if (block_immediately)
        {
            block_ip(ip);
            write_log("IP %s adicionado e bloqueado imediatamente!\n", ip);
        }

        return blocklist_count++;
    }

    return -1; /* Lista cheia */
}

/* Verificar se um IP está bloqueado */
int is_blocked(const char *ip)
{
    for (int i = 0; i < blocklist_count; i++)
    {
        if (strcmp(blocklist[i].ip, ip) == 0 && blocklist[i].blocked)
        {
            return 1;
        }
    }
    return 0;
}

/* Limpar entradas expiradas da blocklist */
void clean_blocklist()
{
    time_t current_time = time(NULL);
    int i = 0;

    while (i < blocklist_count)
    {
        if (current_time - blocklist[i].timestamp > EXPIRATION_TIME)
        {
            /* Desbloquear IP antes de remover da lista */
            if (blocklist[i].blocked)
            {
                unblock_ip(blocklist[i].ip);
                write_log("IP %s desbloqueado (expirado).\n", blocklist[i].ip);
            }

            /* Remover entrada expirada */
            if (i < blocklist_count - 1)
            {
                memmove(&blocklist[i], &blocklist[i + 1], sizeof(BlocklistEntry) * (blocklist_count - i - 1));
            }
            blocklist_count--;
        }
        else
        {
            i++;
        }
    }
}

/* Salvar blocklist em arquivo */
void save_blocklist()
{
    FILE *file = fopen(BLOCKLIST_FILE, "wb");
    if (file == NULL)
    {
        write_log("Erro ao salvar blocklist: %s\n", strerror(errno));
        return;
    }

    fwrite(&blocklist_count, sizeof(blocklist_count), 1, file);
    fwrite(blocklist, sizeof(BlocklistEntry), blocklist_count, file);
    fclose(file);
}

/* Carregar blocklist de arquivo */
void load_blocklist()
{
    FILE *file = fopen(BLOCKLIST_FILE, "rb");
    if (file == NULL)
    {
        write_log("Arquivo de blocklist não encontrado. Criando nova blocklist.\n");
        return;
    }

    fread(&blocklist_count, sizeof(blocklist_count), 1, file);
    if (blocklist_count > MAX_BLOCKLIST_SIZE)
    {
        blocklist_count = MAX_BLOCKLIST_SIZE;
    }

    fread(blocklist, sizeof(BlocklistEntry), blocklist_count, file);
    fclose(file);

    write_log("Blocklist carregada: %d entradas.\n", blocklist_count);

    /* Reativar bloqueios para IPs na lista */
    for (int i = 0; i < blocklist_count; i++)
    {
        if (blocklist[i].blocked)
        {
            block_ip(blocklist[i].ip);
        }
    }
}

/* Inicializar estatísticas de tráfego */
void init_traffic_stats()
{
    stats_count = 0;
    memset(traffic_stats, 0, sizeof(traffic_stats));
}

/* Atualizar estatísticas de tráfego para um IP */
void update_traffic_stats(const char *ip, int is_syn, int is_icmp, int is_udp)
{
    time_t current_time = time(NULL);

    /* Procurar IP nas estatísticas existentes */
    for (int i = 0; i < stats_count; i++)
    {
        if (strcmp(traffic_stats[i].ip, ip) == 0)
        {
            /* Verificar se a janela de tempo foi excedida */
            if (current_time - traffic_stats[i].first_packet > THRESHOLD_WINDOW)
            {
                /* Reiniciar contadores para nova janela */
                traffic_stats[i].first_packet = current_time;
                traffic_stats[i].total_packets = 1;
                traffic_stats[i].syn_packets = is_syn ? 1 : 0;
                traffic_stats[i].icmp_packets = is_icmp ? 1 : 0;
                traffic_stats[i].udp_packets = is_udp ? 1 : 0;
                /* Manter contador de conexões ativas */
            }
            else
            {
                /* Incrementar contadores */
                traffic_stats[i].total_packets++;
                if (is_syn)
                {
                    traffic_stats[i].syn_packets++;
                    traffic_stats[i].active_connections++;
                }
                if (is_icmp)
                    traffic_stats[i].icmp_packets++;
                if (is_udp)
                    traffic_stats[i].udp_packets++;
            }
            return;
        }
    }

    /* Adicionar novo IP se houver espaço */
    if (stats_count < MAX_STATS_ENTRIES)
    {
        strcpy(traffic_stats[stats_count].ip, ip);
        traffic_stats[stats_count].first_packet = current_time;
        traffic_stats[stats_count].total_packets = 1;
        traffic_stats[stats_count].syn_packets = is_syn ? 1 : 0;
        traffic_stats[stats_count].icmp_packets = is_icmp ? 1 : 0;
        traffic_stats[stats_count].udp_packets = is_udp ? 1 : 0;
        traffic_stats[stats_count].active_connections = is_syn ? 1 : 0;
        stats_count++;
    }
}

/* Verificar se há ataques DDoS ativos */
void detect_ddos_attacks()
{
    time_t current_time = time(NULL);

    for (int i = 0; i < stats_count; i++)
    {
        /* Ignorar estatísticas antigas */
        if (current_time - traffic_stats[i].first_packet > THRESHOLD_WINDOW * 2)
        {
            continue;
        }

        int is_attack = 0;
        char attack_type[64] = "";

        /* Verificar diferentes indicadores de ataque */
        if (traffic_stats[i].total_packets > PACKET_THRESHOLD)
        {
            sprintf(attack_type, "alto volume de pacotes: %d", traffic_stats[i].total_packets);
            is_attack = 1;
        }

        if (traffic_stats[i].syn_packets > SYN_THRESHOLD)
        {
            sprintf(attack_type, "SYN flood: %d pacotes SYN", traffic_stats[i].syn_packets);
            is_attack = 1;
        }

        if (traffic_stats[i].icmp_packets > ICMP_THRESHOLD)
        {
            sprintf(attack_type, "ICMP flood: %d pacotes ICMP", traffic_stats[i].icmp_packets);
            is_attack = 1;
        }

        if (traffic_stats[i].udp_packets > UDP_THRESHOLD)
        {
            sprintf(attack_type, "UDP flood: %d pacotes UDP", traffic_stats[i].udp_packets);
            is_attack = 1;
        }

        if (traffic_stats[i].active_connections > MAX_HOST_CONNECTIONS)
        {
            sprintf(attack_type, "múltiplas conexões: %d conexões ativas",
                    traffic_stats[i].active_connections);
            is_attack = 1;
        }

        /* Adicionar à blocklist se for um ataque */
        if (is_attack)
        {
            write_log("Ataque detectado de %s (%s)\n", traffic_stats[i].ip, attack_type);

            pthread_mutex_lock(&blocklist_mutex);
            add_to_blocklist(traffic_stats[i].ip, 1);
            pthread_mutex_unlock(&blocklist_mutex);
        }
    }
}

/* Implementar bloqueio de IP usando iptables */
void block_ip(const char *ip)
{
    char command[256]; // Aumentado o tamanho do buffer

    /* Adicionar regra ao iptables para bloquear o IP */
    snprintf(command, sizeof(command),
             "iptables -A INPUT -s %s -j DROP 2>/dev/null", ip);

    if (system(command) != 0)
    {
        /* Tenta com ipfw se iptables falhar */
        snprintf(command, sizeof(command),
                 "ipfw add deny ip from %s to any 2>/dev/null", ip);

        if (system(command) != 0)
        {
            /* Tenta com pfctl se ipfw também falhar */
            snprintf(command, sizeof(command),
                     "pfctl -t blocklist -T add %s 2>/dev/null", ip);

            if (system(command) != 0)
            {
                write_log("Aviso: Não foi possível bloquear IP %s com nenhum firewall conhecido\n", ip);
                write_log("Certifique-se de estar executando como root/sudo\n");
            }
        }
    }
}

/* Remover bloqueio de IP */
void unblock_ip(const char *ip)
{
    char command[256]; // Aumentado o tamanho do buffer

    /* Tenta remover regra do iptables */
    snprintf(command, sizeof(command),
             "iptables -D INPUT -s %s -j DROP 2>/dev/null", ip);

    if (system(command) != 0)
    {
        /* Tenta com ipfw */
        snprintf(command, sizeof(command),
                 "ipfw delete `ipfw list | grep %s | awk '{print $1}'` 2>/dev/null", ip);

        if (system(command) != 0)
        {
            /* Tenta com pfctl */
            snprintf(command, sizeof(command),
                     "pfctl -t blocklist -T delete %s 2>/dev/null", ip);

            if (system(command) != 0)
            {
                write_log("Aviso: Não foi possível desbloquear IP %s com nenhum firewall conhecido\n", ip);
            }
        }
    }
}

/* Função para escrever em log com timestamp */
void write_log(const char *format, ...)
{
    va_list args;
    time_t now = time(NULL);
    struct tm *timeinfo = localtime(&now);
    char timestamp[20];

    /* Formatar timestamp */
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", timeinfo);

    /* Escrever no arquivo de log */
    fprintf(log_file, "[%s] ", timestamp);

    va_start(args, format);
    vfprintf(log_file, format, args);
    va_end(args);

    fflush(log_file);
}

/* Função para limpeza ao finalizar o programa */
void cleanup_and_exit(int signum)
{
    write_log("Recebido sinal %d. Finalizando...\n", signum);
    running = 0;

    /* Encerrar captura de pacotes */
    pcap_breakloop(pcap_handle);

    /* O resto da limpeza será realizado no thread principal */
}