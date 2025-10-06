#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>

#include <iostream>
#include <string>
#include <cstring>
#include <vector>
#include <utility>

#include <stdint.h>
#include <sys/time.h>

#include "err.h"

using namespace std;

#define BUFFER_SIZE 10

#define HELLO 1
#define HELLO_REPLY 2
#define CONNECT 3
#define ACK_CONNECT 4
#define SYNC_START 11
#define DELAY_REQUEST 12
#define DELAY_RESPONSE 13
#define LEADER 21
#define GET_TIME 31
#define TIME 32

#define MESSAGE 1
#define COUNT 2
#define PEER_ADDRESS_LENGTH 1
#define PEER_PORT 2
#define TIMESTAMP 8
#define SYNCHRONIZED 1

#define UDP_MAX_LEN 65527

static struct timeval start_time;

void init_start_time()
{
    gettimeofday(&start_time, NULL);
}

uint64_t get_timestamp_miliseconds()
{
    struct timeval now;
    gettimeofday(&now, NULL);
    uint64_t seconds = now.tv_sec - start_time.tv_sec;
    int64_t usec_diff = now.tv_usec - start_time.tv_usec;

    return seconds * 1000 + usec_diff / 1000;
}

static uint16_t read_port(char const *string)
{
    char *endptr;
    errno = 0;
    unsigned long port = strtoul(string, &endptr, 10);
    if (errno != 0 || *endptr != 0 || port > UINT16_MAX)
    {
        fatal("%s is not a valid port number", string);
    }
    return (uint16_t)port;
}

static struct sockaddr_in get_server_address(char const *host, uint16_t port)
{
    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    struct addrinfo *address_result;
    int errcode = getaddrinfo(host, NULL, &hints, &address_result);
    if (errcode != 0)
    {
        fatal("getaddrinfo: %s", gai_strerror(errcode));
    }

    struct sockaddr_in send_address;
    send_address.sin_family = AF_INET; // IPv4
    send_address.sin_addr.s_addr =     // IP address
        ((struct sockaddr_in *)(address_result->ai_addr))->sin_addr.s_addr;
    send_address.sin_port = htons(port); // port from the command line

    freeaddrinfo(address_result);

    return send_address;
}

bool equal_sockaddr(struct sockaddr_in sender, struct sockaddr_in prev)
{
    if (sender.sin_port == prev.sin_port && 
        sender.sin_addr.s_addr == prev.sin_addr.s_addr)
    {
        return true;
    }
    return false;
}

static void send_hello(int socket_fd, struct sockaddr_in server_address)
{

    uint8_t message_length = MESSAGE; // tylko typ wiadomości wysyłamy
    uint8_t message[MESSAGE];
    message[0] = HELLO;

    int send_flags = 0;
    ssize_t sent_length = sendto(socket_fd, message, message_length, send_flags,
                                 (struct sockaddr *)&server_address, 
                                 sizeof(server_address));
    if (sent_length < 0)
    {
        syserr("sendto");
    }
    else if ((size_t)sent_length != message_length)
    {
        fatal("incomplete sending");
    }

}

void append_to_buffer(vector<uint8_t> &buffer, 
    uint8_t *to_append_net_order, size_t n_bytes)
{
    for (size_t i = 0; i < n_bytes; i++)
    {
        buffer.push_back(to_append_net_order[i]);
    }
}

void send_hello_reply(int socket_fd, const sockaddr_in &recipient, 
    const vector<sockaddr_in> &peers)
{
    vector<uint8_t> buffer;

    buffer.push_back(HELLO_REPLY);

    uint16_t count = htons(peers.size());
    uint8_t *count_bytes = (uint8_t *)&count;
    append_to_buffer(buffer, count_bytes, 2);

    for (const auto &peer : peers)
    {

        if (equal_sockaddr(peer, recipient))
        {
            continue;
        }

        uint8_t peer_address_length = sizeof(peer.sin_addr);

        buffer.push_back(peer_address_length);

        in_addr_t addr = peer.sin_addr.s_addr;
        uint8_t *addr_bytes = (uint8_t *)&addr;
        append_to_buffer(buffer, addr_bytes, peer_address_length);

        uint16_t port = peer.sin_port;
        append_to_buffer(buffer, (uint8_t *)&port, 2);
    }

    if (buffer.size() > UDP_MAX_LEN)
        return;

    ssize_t sent_length = sendto(socket_fd, buffer.data(), buffer.size(), 0,
                                 (struct sockaddr *)&recipient, sizeof(recipient));
    if (sent_length < 0)
    {
        syserr("sendto");
    }

}

void handle_hello_reply(int socket_fd, const char *buffer, int length,
                        const struct sockaddr_in &client_address, 
                        const struct sockaddr_in &moj_address, 
                        vector<sockaddr_in> &to_who_connect)
{
    int offset = 1; // już odczytaliśmy pierwszy oktet na typ wiadomości
    if (offset + 2 > length)
    {
        error_msg(buffer, length);
        return;
    }
    uint8_t count = ntohs(*(uint16_t *)(buffer + offset));
    offset += 2;

    for (size_t i = 0; i < count; i++)
    {
        if (offset >= length)
        {
            error_msg(buffer, length);
            return;
        }
        uint8_t peer_address_length = buffer[offset];
        offset++;

        if (offset + peer_address_length + 2 > length)
        {
            error_msg(buffer, length);
            return;
        }
        struct sockaddr_in nowy;
        nowy.sin_family = AF_INET;
        if (peer_address_length == 8)
            nowy.sin_family = AF_INET6;

        memcpy(&nowy.sin_addr.s_addr, (buffer + offset), peer_address_length);
        offset += peer_address_length;

        memcpy(&nowy.sin_port, (buffer + offset), 2);
        offset += 2;

        if (equal_sockaddr(nowy, client_address))
        {
            error_msg(buffer, length);
            return;
        }

        if (equal_sockaddr(nowy, moj_address))
        {
            error_msg(buffer, length);
            return;
        }
        uint8_t response[MESSAGE];
        response[0] = CONNECT;

        ssize_t sent_length = sendto(socket_fd, response, sizeof(response), 0,
                                     (struct sockaddr *)&nowy, sizeof(nowy));
        if (sent_length < 0)
        {
            syserr("sendto");
        }
        to_who_connect.push_back(nowy);

    }
}

void handle_connect(int socket_fd, const struct sockaddr_in &client_address)
{

    uint8_t response[MESSAGE];
    response[0] = ACK_CONNECT;

    ssize_t sent_length = sendto(socket_fd, response, sizeof(response), 0,
                                 (struct sockaddr *)&client_address,
                                  sizeof(client_address));
    if (sent_length < 0)
    {
        syserr("sendto");
    }
}

void send_sync_start(int socket_fd, const vector<sockaddr_in> &peers, 
    uint8_t synch, int64_t offset, 
    vector<pair<struct sockaddr_in, uint64_t>> &to_who_send_sync_start)
{

    uint8_t response[MESSAGE + SYNCHRONIZED + TIMESTAMP];
    response[0] = SYNC_START;
    response[1] = synch;
    // wysłać timestamp skorygowany o offset, wysyłam to co wydaje mi się że jest
    // czasem lidera
    to_who_send_sync_start.clear();

    for (const auto &peer : peers)
    {

        uint64_t timestamp = get_timestamp_miliseconds() - offset;
        
        timestamp = htobe64(timestamp);
        memcpy((response + 2), (uint8_t *)&timestamp, 8);

        ssize_t sent_length = sendto(socket_fd, response, sizeof(response), 0,
                                     (struct sockaddr *)&peer, sizeof(peer));
        if (sent_length < 0)
        {
            syserr("sendto");
        }

        to_who_send_sync_start.push_back({peer, get_timestamp_miliseconds()});
    }
}

static void handle_leader(uint8_t synchronizacja, uint8_t &poziom_synch, 
    int64_t &offset, const char *buffer, uint64_t &ostatnie_wyslanie_sync_start)
{

    if (poziom_synch == 0 && synchronizacja == 255)
    {
        poziom_synch = 255;
    }
    else if (synchronizacja == 0)
    {
        poziom_synch = 0;
        offset = 0;
        ostatnie_wyslanie_sync_start = get_timestamp_miliseconds() - 3000;
        // jakby 3s temu wysłał sync_start, więc
        // za 2 sekundy powinien rozpocząć nagłaszanie że jest liderem
    }
    else
    {
        error_msg(buffer, MESSAGE + SYNCHRONIZED);
    }
}

static void handle_get_time(int socket_fd, struct sockaddr_in client_address, 
    int64_t offset, uint8_t poziom_synchronizacji)
{
    // Przygotowujemy odpowiedź: typ + synchronized + timestamp
    uint8_t response[MESSAGE + SYNCHRONIZED + TIMESTAMP]; // razem 10 bajtów
    response[0] = TIME;
    response[1] = poziom_synchronizacji;

    uint64_t timestamp = get_timestamp_miliseconds();
    

    timestamp = htobe64(timestamp - offset);
    memcpy((response + 2), (uint8_t *)&timestamp, 8);

    // Wysyłamy odpowiedź
    ssize_t sent_length = sendto(socket_fd, response, sizeof(response), 0,
                                 (struct sockaddr *)&client_address, 
                                 sizeof(client_address));
    if (sent_length < 0)
    {
        syserr("sendto");
    }
}

bool is_sender_known(const vector<sockaddr_in> &peers, 
    struct sockaddr_in client_address)
{
    for (const auto &peer : peers)
    {
        if (equal_sockaddr(peer, client_address))
        {
            return true;
        }
    }
    return false;
}

bool is_sender_known_pair(const vector<pair<sockaddr_in, uint64_t>> &peers, 
    struct sockaddr_in client_address)
{
    for (const auto &peer : peers)
    {
        if (equal_sockaddr(peer.first, client_address))
        {
            return true;
        }
    }
    return false;
}

bool too_old(const vector<pair<sockaddr_in, uint64_t>> &peers, 
    struct sockaddr_in client_address)
{
    for (const auto &peer : peers)
    {
        if (equal_sockaddr(peer.first, client_address))
        {
            if (get_timestamp_miliseconds() - peer.second > 6000)
            { // 6s
                return true;
            }
        }
    }
    return false;
}

void handle_delay_request(int socket_fd, int poziom_synch, uint64_t T4,
                          struct sockaddr_in client)
{

    uint8_t response[MESSAGE + SYNCHRONIZED + TIMESTAMP]; // razem 10 bajtów
    response[0] = DELAY_RESPONSE;
    response[1] = poziom_synch;

    uint64_t timestamp = T4;
    timestamp = htobe64(timestamp);
    memcpy((response + 2), (uint8_t *)&timestamp, 8);

    ssize_t sent_length = sendto(socket_fd, response, sizeof(response), 0,
                                 (struct sockaddr *)&client, sizeof(client));

    if (sent_length < 0)
    {
        syserr("sendto");
    }
}

void handle_delay_response(uint8_t &poziom_synch, int64_t &offset,
                           struct sockaddr_in &z_kim__zsynchronizowany, 
                           uint8_t poziom_z_kim_sie_synchronizuje, 
                           uint64_t T1, uint64_t T2, uint64_t T3,
                           bool &w_trakcie_synchronizacji, const char *buffer, 
                           struct sockaddr_in client)
{

    size_t index = 1; // msg odczytany

    uint8_t synch_nadawcy = buffer[index];
    index++;
    uint64_t T4 = be64toh(*(uint64_t *)(buffer + index));
    if (poziom_z_kim_sie_synchronizuje != synch_nadawcy)
    {
        error_msg(buffer, MESSAGE + SYNCHRONIZED + TIMESTAMP);
        w_trakcie_synchronizacji = false;
        return;
    }

    if (poziom_synch == 0)
        return;

    offset = ((int64_t)T2 - (int64_t)T1 + (int64_t)T3 - (int64_t)T4) / 2;
    poziom_synch = synch_nadawcy + 1;

    z_kim__zsynchronizowany = client;
    w_trakcie_synchronizacji = false;
}

void handle_sync_start(int socket_fd, uint8_t &poziom_synch,
                       struct sockaddr_in &z_kim__zsynchronizowany, 
                       uint64_t &T1, uint64_t &T3,
                       struct sockaddr_in &z_kim_sie_synchronizuje, 
                       uint8_t &poziom_z_kim_sie_synchronizuje, 
                       bool &w_trakcie_synchronizacji,
                       const char *buffer, struct sockaddr_in client, 
                       uint64_t &ostatnie_odebranie_sync_start, 
                       pair<struct sockaddr_in, uint64_t> &to_who_send_delay_req)
{

    size_t index = 1; // msg odczytany

    uint8_t synch_nadawcy = buffer[index];
    index++;
    if (synch_nadawcy >= 254)
        return;
    if (poziom_synch == 0)
        return;
    if (equal_sockaddr(z_kim__zsynchronizowany, client))
    {
        if (synch_nadawcy >= poziom_synch)
        {
            poziom_synch = 255;
            return;
        }
    }
    else
    {
        if (poziom_synch == 1 && synch_nadawcy == 0)
        {
            /* zmiana lidera, nie odpowiadamy */
            return;
        }
        if (!(synch_nadawcy <= poziom_synch - 2))
            return;
    }
    z_kim_sie_synchronizuje = client;
    w_trakcie_synchronizacji = true;
    poziom_z_kim_sie_synchronizuje = synch_nadawcy;

    T1 = be64toh(*(uint64_t *)(buffer + index));

    uint8_t response[MESSAGE];
    response[0] = DELAY_REQUEST;

    T3 = get_timestamp_miliseconds();

    ssize_t sent_length = sendto(socket_fd, response, sizeof(response), 0,
                                 (struct sockaddr *)&client, sizeof(client));
    if (sent_length < 0)
    {
        syserr("sendto ");
    }

    ostatnie_odebranie_sync_start = get_timestamp_miliseconds();
    to_who_send_delay_req.first = client;
    to_who_send_delay_req.second = get_timestamp_miliseconds();
}

int socket_udp()
{

    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0)
    {
        syserr("cannot create a socket");
    }

    if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof(timeout)) < 0)
        syserr("setsockopt failed\n");

    if (setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                   sizeof(timeout)) < 0)
        syserr("setsockopt failed\n");
    return socket_fd;
}

int main(int argc, char *argv[])
{

    init_start_time(); // uruchomienie zegara

    vector<struct sockaddr_in> peers;
    vector<struct sockaddr_in> to_who_send_connect;

    vector<pair<struct sockaddr_in, uint64_t>> to_who_send_sync_start;
    pair<struct sockaddr_in, uint64_t> to_who_send_delay_req;

    int64_t offset;
    uint8_t poziom_synchronizacji = 255; // nie jest z nikim zsynchronizowany
    struct sockaddr_in z_kim_zsynchronizowany;

    uint64_t T1 = 0;
    uint64_t T2 = 0;
    uint64_t T3 = 0;

    bool w_trakcie_synchronizacji = false;
    struct sockaddr_in z_kim_sie_synchronizuje;
    uint8_t poziom_z_kim_sie_synchronizuje;

    char const *bind_address = ""; // nasłuchuj na wszystkich interfejsach
    uint16_t port = 0;             // dowolny port
    char const *peer_address = "";
    uint16_t peer_port = 0; // 0 oznacza "nieustawiony"

    // Przyjmujemy ostatnią wartość parametru w przypadku podania kilka
    // razy wartości parametru tego samego typu

    for (int i = 1; i < argc; ++i)
    {
        if (strcmp(argv[i], "-b") == 0)
        {
            if (i + 1 < argc)
                bind_address = argv[++i];
            else
                fatal("Brak argumentu dla -b\n");
        }
        else if (strcmp(argv[i], "-p") == 0)
        {
            if (i + 1 < argc)
                port = read_port(argv[++i]);
            else
                fatal("Brak argumentu dla -p\n");
        }
        else if (strcmp(argv[i], "-a") == 0)
        {
            if (i + 1 < argc)
                peer_address = argv[++i];
            else
                fatal("Brak argumentu dla -a\n");
        }
        else if (strcmp(argv[i], "-r") == 0)
        {
            if (i + 1 < argc)
                peer_port = read_port(argv[++i]);
            else
                fatal("Brak argumentu dla -r\n");
        }
        else
            fatal("Nieznany argument: %s\n", argv[i]);
    }

    int socket_fd = socket_udp();

    // Przygotowujemy adresu do nasłuchiwania
    struct sockaddr_in address_do_nasluchu;
    address_do_nasluchu.sin_family = AF_INET;   // IPv4
    address_do_nasluchu.sin_port = htons(port); // Port użytkownika

    if (!strcmp(bind_address, "") == 0)
    {
        
        if (inet_pton(AF_INET, bind_address, &address_do_nasluchu.sin_addr) <= 0)
        {
            syserr("invalid IP address");
        }
    }
    else
    {
        address_do_nasluchu.sin_addr.s_addr = htonl(INADDR_ANY); 
        // nasłuchujemy na wszystkich adresach hosta
    }

    // Bindowanie gniazda do określonego adresu IP i portu
    if (bind(socket_fd, (struct sockaddr *)&address_do_nasluchu, 
        (socklen_t)sizeof(address_do_nasluchu)) < 0)
    {
        syserr("bind");
    }

    if (port == 0)
    { // dowiedzenie się jaki port się wybrał (można usunąć)
        socklen_t len = sizeof(address_do_nasluchu);
        if (getsockname(socket_fd, 
            (struct sockaddr *)&address_do_nasluchu, &len) == -1)
        {
            syserr("getsockname failed");
        }
        port = ntohs(address_do_nasluchu.sin_port);
    }
    // Sprawdzanie warunku: jeśli podano -a, to musi być też -r (i odwrotnie)
    bool a_set = !(strcmp(peer_address, "") == 0);
    bool r_set = (peer_port != 0);

    struct sockaddr_in hello_address;
    if (a_set != r_set)
    {
        fatal("Parametry -a i -r muszą być podane razem.\n");
    }
    else if (a_set && r_set)
    {
        hello_address = get_server_address(peer_address, peer_port);
        send_hello(socket_fd, hello_address);
    }

    // nasłuchiwanie

    uint64_t ostatnie_wyslanie_sync_start = get_timestamp_miliseconds() - 5000;
       // ponad 5s temu
    uint64_t ostatnie_odebranie_sync_start = get_timestamp_miliseconds() - 30000; 
        // rozsynchronizowany
                                 

    while (true)
    {
        static char buffer[UDP_MAX_LEN + 1];
        memset(buffer, 0, sizeof(buffer));

        int flags = 0;
        struct sockaddr_in client_address;
        socklen_t address_length = (socklen_t)sizeof(client_address);

        int received_length = recvfrom(socket_fd, buffer, UDP_MAX_LEN, flags,
                                       (struct sockaddr *)&client_address, 
                                       &address_length);
        bool skip_switch = false;
        if (received_length < 0)
        {
            if (received_length == -1)
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                {
                    skip_switch = true;
                    errno = 0;
                }
            }
            else
            {
                syserr("recvfrom");
            }
        }
        if (received_length == 0)
        {
            error_msg(buffer, 0);
            skip_switch = true;
        }
        if (!skip_switch)
        {
            uint8_t message_type = (uint8_t)buffer[0];

            switch (message_type)
            {
            case HELLO:
                if (received_length != MESSAGE)
                {
                    error_msg(buffer, received_length);
                    break;
                }
                send_hello_reply(socket_fd, client_address, peers);
                peers.push_back(client_address);
                break;
            case HELLO_REPLY:

                if (!a_set || !equal_sockaddr(client_address, hello_address))
                {
                    error_msg(buffer, received_length);
                    break;
                }
                peers.push_back(client_address);

                handle_hello_reply(socket_fd, buffer, received_length, 
                    client_address, address_do_nasluchu, to_who_send_connect);

                break;
            case CONNECT:
                if (received_length != MESSAGE)
                {
                    error_msg(buffer, received_length);
                    break;
                }
                peers.push_back(client_address);
                handle_connect(socket_fd, client_address);
                break;
            case ACK_CONNECT:
                if (received_length != MESSAGE || 
                    !is_sender_known(to_who_send_connect, client_address))
                {
                    error_msg(buffer, received_length);
                    break;
                }
                peers.push_back(client_address);
                break;
            case SYNC_START:
                if (received_length != MESSAGE + SYNCHRONIZED + TIMESTAMP || 
                    !is_sender_known(peers, client_address))
                {
                    error_msg(buffer, received_length);
                    break;
                }
                if (w_trakcie_synchronizacji)
                    break;

                T2 = get_timestamp_miliseconds();

                handle_sync_start(socket_fd, poziom_synchronizacji,
                                  z_kim_zsynchronizowany, T1, T3, 
                                  z_kim_sie_synchronizuje,
                                  poziom_z_kim_sie_synchronizuje,
                                  w_trakcie_synchronizacji, buffer, 
                                  client_address, ostatnie_odebranie_sync_start,
                                    to_who_send_delay_req);

                break;
            case DELAY_REQUEST:
                if (received_length != MESSAGE)
                {
                    error_msg(buffer, received_length);
                    break;
                }
                if (!is_sender_known_pair(to_who_send_sync_start, client_address))
                {
                    error_msg(buffer, received_length);
                    break;
                }
                if (too_old(to_who_send_sync_start, client_address))
                {
                    break;
                }
                handle_delay_request(socket_fd, poziom_synchronizacji,
                                     get_timestamp_miliseconds() - offset, 
                                     client_address);

                break;
            case DELAY_RESPONSE:
                if (received_length != MESSAGE + SYNCHRONIZED + TIMESTAMP)
                {
                    error_msg(buffer, received_length);
                    break;
                }
                if (!equal_sockaddr(to_who_send_delay_req.first, client_address))
                {
                    error_msg(buffer, received_length);
                    break;
                }
                if (get_timestamp_miliseconds() - to_who_send_delay_req.second > 5000)
                {
                    break;
                }
                handle_delay_response(poziom_synchronizacji, offset,
                                      z_kim_zsynchronizowany, 
                                      poziom_z_kim_sie_synchronizuje, T1, T2, 
                                      T3, w_trakcie_synchronizacji,
                                      buffer, client_address);

                break;
            case LEADER:
                if (received_length != MESSAGE + SYNCHRONIZED)
                {
                    error_msg(buffer, received_length);
                    break;
                }
                handle_leader((uint8_t)buffer[1], poziom_synchronizacji, offset, 
                    buffer, ostatnie_wyslanie_sync_start);
                w_trakcie_synchronizacji = false;
                break;
            case GET_TIME:
                if (received_length != MESSAGE)
                {
                    error_msg(buffer, received_length);
                    break;
                }
                handle_get_time(socket_fd, client_address, offset,
                                poziom_synchronizacji);
                break;
            default:
                error_msg(buffer, received_length);
            }
        }
        
        if (poziom_synchronizacji != 0 &&
            get_timestamp_miliseconds() - ostatnie_odebranie_sync_start > 30000)
        {
            poziom_synchronizacji = 255;
            offset = 0;
            w_trakcie_synchronizacji = false;
        }

        if (poziom_synchronizacji < 254 &&
            get_timestamp_miliseconds() - ostatnie_wyslanie_sync_start > 5000)
        {
            send_sync_start(socket_fd, peers, poziom_synchronizacji, offset, 
                to_who_send_sync_start);
            ostatnie_wyslanie_sync_start = get_timestamp_miliseconds();
        }
    }
    return 0;
}
