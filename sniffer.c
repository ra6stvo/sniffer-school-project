// Привет, это пример сниффера, который вы сможете рассматривать при написании кода для собственного анализатора сетевых данных. Он выполняет несколько примитивных функций и является эталоном в моей практической работе. Расскажу о том, что как работает этот код: программа предоставляет пользователю выбор интерфейса из доступных на его устройстве; на выбранном интерфейсе запускается прослушка; далее программа перехватывает первые 10 пакетов, передающихся по сети и отправляет их на обработку, которая впоследствии выводит информацию об этом пакете; сама программа разбирает только 5 протоколов, ведь она является лишь примером, который вы можете дополнить, например: добавить функцию обработки некоторых других сетевых протоколов. 
// Ресурсы, которые помогут ознакомиться с используемыми функциями, узнать об их работе:
// 1. Сайт библиотеки libpcap (основная библиотека) - https://www.tcpdump.org
// 2. Библиотека libpcap на github (также необходимо для установки данной библиотеки) - https://github.com/the-tcpdump-group/libpcap

// - Объявление заголовков используемых в коде библиотек
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>

// - Теперь нам нужно объявить структуры обрабатываемых нашим кодом протоколов, которые будут содержать информацию о сетевом пакете. Они необходимы для удобного перемещения по дампу пакета.

// Структура Ethernet заголовка
struct ethernet_header {
    unsigned char dest[6];
    unsigned char src[6];
    unsigned char type[2]; 
};

// Структура IP заголовка
struct ip_header {
    unsigned char ihl:4;
    unsigned char version:4;
    unsigned char tos;
    unsigned char total_length[2]; 
    unsigned char id[2]; 
    unsigned char frag_off[2]; 
    unsigned char ttl;
    unsigned char protocol;
    unsigned char checksum[2]; 
    struct in_addr src_addr;
    struct in_addr dest_addr;
};

// Структура ICMP заголовка
struct icmp_header {
    unsigned char type;
    unsigned char code;
    unsigned char checksum[2]; 
    unsigned char id[2]; 
    unsigned char sequence[2]; 
};

// Структура IGMP заголовка
struct igmp_header {
    unsigned char type;
    unsigned char max_resp_time;
    unsigned char checksum[2]; 
    struct in_addr group_address;
};

// Структура TCP заголовка
struct tcp_header {
    unsigned char src_port[2]; 
    unsigned char dest_port[2]; 
    unsigned char seq_num[4]; 
    unsigned char ack_num[4]; 
    unsigned char offset:4;
    unsigned char reserved:4;
    unsigned char flags;
    unsigned char window[2]; 
    unsigned char checksum[2]; 
    unsigned char urgent_ptr[2]; 
};

// Структура UDP заголовка
struct udp_header {
    unsigned char src_port[2]; 
    unsigned char dest_port[2]; 
    unsigned char length[2]; 
    unsigned char checksum[2]; 
};

// Структура ARP заголовка
struct arp_header {
    unsigned char hw_type[2]; 
    unsigned char proto_type[2]; 
    unsigned char hw_size;
    unsigned char proto_size;
    unsigned char opcode[2]; 
    unsigned char sender_hw_addr[6];
    struct in_addr sender_proto_addr;
    unsigned char target_hw_addr[6];
    struct in_addr target_proto_addr;
};

// - Чтобы привести данные пакета в соответствие с приведенными структурами, необходимо преобразовать сетевой пакет в шестнадцатеричный дамп. Выводить информацию о пакете мы будем в виде шестнадцатеричных значений

void print_hex(const unsigned char *data, int length) { // Преобразование пакета в шестнадцатеричный дамп
    for (int i = 0; i < length; i++) {
        printf("%02x ", data[i]);
    }
}

// Функция обработки пакетов. Программа проходит по шестнадцатеричному дампу пакета, выводя информацию о заголовках исходя из указанных выше структур и длины дампа пакета. см. подробнее в прикрепленных ресурсах

void process_packet(const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethernet_header *eth = (struct ethernet_header *)packet;

// Вывод информации о сетевом пакете, далее вы увидите тот же самый процесс, по сути, это и есть обработка перехваченного пакета
    printf("Ethernet Header:\n");
    printf("  Source MAC: ");
    print_hex(eth->src, sizeof(eth->src));
    printf("\n  Destination MAC: ");
    print_hex(eth->dest, sizeof(eth->dest));
    
    printf("\n  Type: ");
    print_hex(eth->type, sizeof(eth->type));
    
    // Определяем тип протокола исходя из структуры Ethernet заголовка (узнаем первые 2 байта дампа, они содержат информацию о типе следующего заголовка)
    if (eth->type[0] == 0x08 && eth->type[1] == 0x00) { // IPv4
        struct ip_header *ip = (struct ip_header *)(packet + sizeof(struct ethernet_header));
        printf("\nIP Header:\n");
        printf("  Source IP: %s\n", inet_ntoa(ip->src_addr));
        printf("  Destination IP: %s\n", inet_ntoa(ip->dest_addr));
        printf("  Protocol: %d\n", ip->protocol);

        // Обработка пакетов протоколов TCP, UDP, ICMP и IGMP. Протокол пакета определяется из структуры IP заголовка (узнаем последние 2 байта IP протокола, они содержат информацию о протоколе следующего заголовка)
        if (ip->protocol == 6) { // TCP
            struct tcp_header *tcp = (struct tcp_header *)(packet + sizeof(struct ethernet_header) + sizeof(struct ip_header)); // На этом шаге мы разбиваем дамп пакета на различные данные, используя его постоянную длину
            printf("TCP Header:\n");
            printf("  Source Port: ");
            print_hex(tcp->src_port, sizeof(tcp->src_port));
            printf("\n  Destination Port: ");
            print_hex(tcp->dest_port, sizeof(tcp->dest_port));

	// Прописываем аналогично функцию обработки для остальных протоколов
	
        } else if (ip->protocol == 17) { // UDP
            struct udp_header *udp = (struct udp_header *)(packet + sizeof(struct ethernet_header) + sizeof(struct ip_header));
            printf("UDP Header:\n");
            printf("  Source Port: ");
            print_hex(udp->src_port, sizeof(udp->src_port));
            printf("\n  Destination Port: ");
            print_hex(udp->dest_port, sizeof(udp->dest_port));
        } else if (ip->protocol == 1) { // ICMP
            struct icmp_header *icmp = (struct icmp_header *)(packet + sizeof(struct ethernet_header) + sizeof(struct ip_header));
            printf("ICMP Header:\n");
            printf("  Type: %d\n", icmp->type);
            printf("  Code: %d\n", icmp->code);
        } else if (ip->protocol == 2) { // IGMP
            struct igmp_header *igmp = (struct igmp_header *)(packet + sizeof(struct ethernet_header) + sizeof(struct ip_header));
            printf("IGMP Header:\n");
            printf("  Type: %d\n", igmp->type);
            printf("  Group Address: %s\n", inet_ntoa(igmp->group_address));
        }
    } else if (eth->type[0] == 0x08 && eth->type[1] == 0x06) { // ARP
        struct arp_header *arp = (struct arp_header *)(packet + sizeof(struct ethernet_header));
        printf("\nARP Header:\n");
        printf("  Sender IP: %s\n", inet_ntoa(arp->sender_proto_addr));
        printf("  Target IP: %s\n", inet_ntoa(arp->target_proto_addr));
    } else {
        printf("Unknown Protocol Type: %02x%02x\n", eth->type[0], eth->type[1]); // Пакет имеет протокол, который не обрабатывается в данной в функции, он не проверяется соответственно
    }
}

// Функция для перехвата пакетов, далее будет использоваться в функции pcap_dispatch()
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    process_packet(header, packet);
}

void list_interfaces() {
    pcap_if_t *alldevs;
    pcap_if_t *device;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Получаем список интерфейсов при помощи функции pcap_findalldevs(), одним из аргументов которой является переменная errbuf, она предназначена для выявления ошибок в процессах выполнения некоторых функций библиотеки libpcap. см. подробнее в прикрепленных ресурсах
    if (pcap_findalldevs(&alldevs, errbuf) == -1) { // Если значение errbuf равно -1, то программа определяет, что при получении списка интерфейсов возникает ошибка
        fprintf(stderr, "Ошибка при получении списка интерфейсов: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    printf("Доступные интерфейсы:\n"); // Вывод интерфейсов, доступных для запуска прослушки
    int index = 0;
    for (device = alldevs; device != NULL; device = device->next) {
        printf("[%d] %s\n", index++, device->name);
    }

    // Освобождаем память при помощи функции pcap_freealldevs(), см. подробнее в прикрепленных ресурсах
    pcap_freealldevs(alldevs);
}

int main() {
    pcap_if_t *alldevs;
    pcap_if_t *device;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    list_interfaces();

    int choice = -1;

    // Цикл для предоставления выбора интерфейса пользователю, выбор соответсвенно записывается в переменную choice
    while (choice < 0) {
        printf("Введите номер интерфейса для перехвата пакетов: ");
        scanf("%d", &choice);

        // Проверяем существует ли интерфейс при помощи функции pcap_findalldevs(), см. подробнее в прикрепленных ресурсах
        if (pcap_findalldevs(&alldevs, errbuf) == -1) { // Ошибка описана в комментариях выше
            fprintf(stderr, "Ошибка при получении списка интерфейсов: %s\n", errbuf);
            exit(EXIT_FAILURE);
        }

        int index = 0;
        for (device = alldevs; device != NULL; device = device->next) { // Проверка на совпадение выбранного пользователя интерфейса с интерфейсами в списке доступных для прослушки интерфейсов
            if (index == choice) {
                break; // Найден выбранный интерфейс
            }
            index++;
        }

        if (device != NULL) {
            printf("Запуск перехвата пакетов на интерфейсе: %s\n", device->name);
            pcap_t *handle; // Сообщает о запуске перехвата пакетов

            // Открываем интерфейс для захвата при помощи pcap_open_live(), одним из аргументов которой является выбранный нами интерфейс, а также буфер ошибок errbuf, см. подробнее в прикрепленных ресурсах
            handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
			
            if (handle == NULL) {
                fprintf(stderr, "Не удалось открыть интерфейс %s: %s\n", device->name, errbuf); // Ошибка при открытии выбранного интерфейса. До этого мы присвоили переменной handle значение функции pcap_open_live(), соответственно, если эта переменная пустая - прослушка не была запущена
                return 1; 
            }

            // Перехватываем первые 10 пакетов при помощи функции pcap_dispatch() и отправляем их на функцию обработки packet_handler(), описанную выше, см. подробнее в прикрепленных ресурсах
            pcap_dispatch(handle, 10, packet_handler, NULL);

            pcap_close(handle);
            break; // Выход из цикла после успешного захвата, при помощи функции pcap_close(), см. подробнее в прикрепленных ресурсах
        } else {
            printf("Неверный номер интерфейса. Пожалуйста, попробуйте снова.\n"); // Проверка на наличие подобного интерфейса в списке
            choice = -1; // Сброс выбора для повторного ввода
        }

        pcap_freealldevs(alldevs); // Освобождаем ресурсы при помощи функции pcap_freealldevs(), см. подробнее в прикрепленных ресурсах
    }

    return 0;
}
