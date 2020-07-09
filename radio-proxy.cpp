#include <iostream>
#include <regex>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <csignal>
#include <ctime>
#include <poll.h>

#include "err.h"

/*** CONSTANTS ***/

// serveLine states
#define INPUT_HEADER 0
#define READING_OUT 1
#define READING_BYTE 2
#define READING_ERR 3

// Evacuation states
#define SOCKTCP 1
#define SOCKUDP 2
#define ALL     4

// UDP types
#define DISCOVER 1
#define IAM 2
#define KEEPALIVE 3
#define AUDIO 4
#define METADATA 6

// modes
#define MODE_A 1
#define MODE_B1 2
#define MODE_B2 3

// others
#define THREAD_NUM 3
#define BSIZE 1024
#define CLIENT_SIZE 4

using namespace std;

/*** GLOBAL VARIABLES ***/

// There are three modes, depending on the given arguments
int mode = 0;

// Name of the radio we are listening to
//string name;
char name[BSIZE];
size_t nameLen = 0;
bool nameSet = false;

// Do we expect metedata?
bool requireMeta = false;

// Name of the source host
string hostname;
bool hostnameSet = false;

// Name of the resource we are downloading
string resource;
bool resourceSet = false;

// Source port
string srcPort;
bool srcPortSet = false;

// Multicast address
string multiAdr;
bool multiAdrSet = false;

// Port of client socket
string cliPort;
bool cliPortSet = false;

// Timeout for source
int sourceTimeout = 5;

// Timeout for each client
int clientTimeout = 5;

// Key – unique for address and port, val – time_t of last discover/keepalive (if it is actually alive)
map<unsigned long long, time_t>* listenMap;

// Memory for a header
char header[BSIZE * BSIZE * BSIZE];

// Length of header string
int headerLen = 0;
struct addrinfo *addr_result;

// Number of bytes left to end of a state
int toGo = 0;

// Here will be icy-metaint
int outDefault = -1;

// Current reading line state
int state = INPUT_HEADER;

// Poll of two sockets – one for TCP and one for UDP
struct pollfd socks[THREAD_NUM];

// Checks if it is the end of header
bool isEmptyLine() {
  return header[headerLen-1] == 10
      && header[headerLen-2] == 13
      && header[headerLen-3] == 10
      && header[headerLen-4] == 13;
}

// Creates a key from address and port
unsigned long long portKey(struct sockaddr_in input) {
  return (unsigned long long)input.sin_addr.s_addr * 65536 + (unsigned long long)input.sin_port;
}

// Evacuation
void evacuate(int phase, bool sys, string what) {
  if (ALL) {
    delete listenMap;
  }

  if (SOCKTCP) {
    close(socks[0].fd);
  }

  if (mode != MODE_A) {
    close(socks[1].fd);
  }

  if (sys)
    syserr(what.c_str());
  else
    fatal(what.c_str());
}

// Converts string to int (-1 in case of false value)
int toInt(string s) {
  string max = "2147483647";
  if (s.size() > 10)
    return -1;
  else if (s.size() == 10) {
    for (int i = 0; i < 10; i++) {
      if (s[i] < max[i])
        break;
      else if (s[i] > max[i])
        return -1;
    }
  }

  return stoi(s);
}

// Given the header, gets important information
bool getFromHeader() {
  int l = 0;
  bool lower = true; // Says if the parameter is not data and we can lower it
  bool first = true; // Says if we have to do with first line of header
  char line[BSIZE*BSIZE];

  for (int i = 0; i < headerLen; i++) {
    // If colon, data begins
    if (header[i] == ':')
      lower = false;

    // if not data and UPPER, we have to lower it
    if (lower && header[i] >= 65 && header[i] <= 90) {
      header[i] += 32;
    }
    line[l++] = header[i];

    // If end of line, we look for data
    if (i > 0 && header[i-1] == 13 && header[i] == 10) {
      lower = true; // end of data

      // Check if OK
      if (first) {
        line[l - 2] = '\0';
        first = false;
        if (strncmp(line, "icy 200 ok", 10) != 0
            && strncmp(line, "http/1.0 200 ok", 15) != 0
            && strncmp(line, "http/1.1 200 ok", 15) != 0) {
          return false;
        }
      } else if (!strncmp(line, "icy-metaint: ", 12)) { // Check if metaint
        line[l - 2] = '\0';
        string tmp(line+12);

        // saving metaint to outDefault
        outDefault = toInt(tmp);
        toGo = outDefault;

        if (outDefault == -1) {
          return false;
        }
      } else if (!strncmp(line, "icy-name:", 9)) { // Check if icy-name
        // then we have got a name
        line[l - 2] = '\0';

        // Saving icy-name to name
        nameSet = true;

        for (size_t j = 0; j < l - 11; j++) {
          name[j] = line[9 + j];
        }

        nameLen = l - 11;
      }
      line[l] = '\0';
      l = 0;
    }
  }
  return true;
}

// Given the line, goes through it
void serveLine(const char* resp, int read) {
  char mp3[BSIZE], meta[BSIZE];
  char audioCom[BSIZE+CLIENT_SIZE], metaCom[BSIZE+CLIENT_SIZE];
  size_t mp3Len = 0, metaLen = 0;

  for (int i = 0; i < read; i++) {
    if (state == INPUT_HEADER) { // Reading to header
      header[headerLen++] = resp[i];
      if (headerLen > 4 && isEmptyLine()) {
        if (!getFromHeader() || (!nameSet && mode != MODE_A)) {
          close(socks[0].fd);

          if (mode != MODE_A)
            close(socks[1].fd);

          delete listenMap;
          exit(1);
        }

        toGo = outDefault;
        state = READING_OUT;
      }
    } else if (state == READING_OUT && outDefault == -1) { // Reading to AUDIO
      if (mode == MODE_A)
        printf("%c", resp[i]);
      audioCom[4+mp3Len] = resp[i];
      mp3[mp3Len++] = resp[i];
    } else if (state == READING_OUT && toGo > 0) { // Reading to AUDIO if metaint
      toGo--;
      if (mode == MODE_A)
        printf("%c", resp[i]);
      audioCom[4+mp3Len] = resp[i];
      mp3[mp3Len++] = resp[i];
      if (toGo == 0) {
        state = READING_BYTE;
      }
    } else if (state == READING_BYTE) { // Reading, how much meta we have to read
      toGo = resp[i] * 16;
      if (toGo == 0) {
        state = READING_OUT;
        toGo = outDefault;
      } else
        state = READING_ERR;
    } else if (state == READING_ERR && toGo > 0) { // Reading metadata
      toGo--;
      if (mode == MODE_A)
        fprintf(stderr, "%c", resp[i]);
      metaCom[4+metaLen] = resp[i];
      meta[metaLen++] = resp[i];

      if (toGo == 0) {
        state = READING_OUT;
        toGo = outDefault;
      }
    } else {
      exit(1);
    }
  }

  // Sends data to clients that are alive
  for(auto & i : *listenMap) {
    if (difftime(time(nullptr), i.second) < clientTimeout) {

      struct sockaddr_in cliAddr{};
      cliAddr.sin_family = AF_INET;
      cliAddr.sin_addr.s_addr = (in_addr_t) (i.first / 65536);
      cliAddr.sin_port = (in_port_t) i.first % 65536;

      *((uint16_t*) audioCom) = htons(AUDIO);
      *((uint16_t*) &audioCom[2]) = htons(mp3Len);

      sendto(socks[1].fd, audioCom, CLIENT_SIZE + mp3Len, 0,
             (struct sockaddr*)&(cliAddr), (socklen_t)sizeof(cliAddr));
      *((uint16_t*) metaCom) = htons(METADATA);
      *((uint16_t*) &metaCom[2]) = htons(metaLen);

      sendto(socks[1].fd, metaCom, CLIENT_SIZE + metaLen,
             0, (struct sockaddr*)&(cliAddr), (socklen_t)sizeof(cliAddr));
    }
  }
}

// Serves SIGINT
static void catch_int (__attribute__((unused)) int sig) {

  delete listenMap;

  // Closing TCP socket
  if (close(socks[0].fd) < 0) {
    fatal("Closing stream socket failed");
  }

  // Closing UDP socket
  if (mode != MODE_A) {
    if (close(socks[1].fd) < 0) {
      fatal("Closing stream socket failed");
    }
  }

  exit(0);
}

int main(int argc, char *argv[]) {
  sigset_t block_mask;

  // After Ctrl+C we end
  sigemptyset (&block_mask);
  struct sigaction action{};
  action.sa_handler = catch_int;
  action.sa_mask = block_mask;
  action.sa_flags = SA_RESTART;

  if (sigaction (SIGINT, &action, nullptr) == -1)
    syserr("sigaction");

  // At least one parameter must be
  if (argc == 1 || argc % 2 == 0) {
    fatal("Invalid number of parametres");
  }

  // Reading parametres
  for (int i = 1; i < argc; i+= 2) {
    string firstParam = argv[i];
    string secondParam = argv[i+1];
    smatch match;
    if (firstParam == "-h") {
      hostnameSet = true;
      hostname = secondParam;
    } else if (firstParam == "-r") {
      resourceSet = true;
      resource = secondParam;
    } else if (firstParam == "-p") {
      regex number("([0-9]*)");
      if (!regex_match(secondParam, match, number))
        fatal("Invalid arg or flag instead of arg");
      int portNum = toInt(secondParam);
      if (portNum < 1 || portNum > 65535)
        fatal("Invalid arg or flag instead of arg");
      srcPortSet = true;
      srcPort = secondParam;
    } else if (firstParam == "-m") {
      if (secondParam == "yes") {
        requireMeta = true;
      } else if (secondParam == "no") {
        requireMeta = false;
      } else
        fatal("Non-binary -m parameter");
    } else if (firstParam == "-t") {
      regex number("([0-9]*)");
      if (!regex_match(secondParam, match, number))
        fatal("Invalid arg or flag instead of arg");
      sourceTimeout = toInt(secondParam);
      if (sourceTimeout == -1 || sourceTimeout == 0)
        fatal("Invalid arg or flag instead of arg");
    } else if (firstParam == "-P") {
      regex number("([0-9]*)");
      if (!regex_match(secondParam, match, number))
        fatal("Invalid arg or flag instead of arg");
      int portNum = toInt(secondParam);
      if (portNum == -1 || portNum > 65535)
        fatal("Invalid arg or flag instead of arg");
      cliPortSet = true;
      cliPort = secondParam;
    } else if (firstParam == "-B") {
      multiAdrSet = true;
      multiAdr = secondParam;
    } else if (firstParam == "-T") {
      regex number("([0-9]*)");
      if (!regex_match(secondParam, match, number))
        fatal("Invalid arg or flag instead of arg");
      clientTimeout = toInt(secondParam);
      if (clientTimeout == -1 || clientTimeout == 0)
        fatal("Invalid arg or flag instead of arg");
    } else
      fatal("Invalid flag or arg instead of flag");
  }

  // Choosing mode
  if (hostnameSet && resourceSet && srcPortSet && cliPortSet && multiAdrSet) {
    mode = MODE_B2;
  } else if (hostnameSet && resourceSet && srcPortSet && cliPortSet && !multiAdrSet) {
    mode = MODE_B1;
  } else if (hostnameSet && resourceSet && srcPortSet && !cliPortSet && !multiAdrSet) {
    mode = MODE_A;
  } else {
    fatal("Invalid arg set");
  }

  struct addrinfo addr_hints{};

  // If mode B, we create UDP socket
  if (mode != MODE_A) {
    // creating a socket
    socks[1].fd = socket(AF_INET, SOCK_DGRAM, 0);
    socks[1].events = POLLIN;
    socks[1].revents = 0;
    if (socks[1].fd < 0)
      syserr("socket UDP");

    // if we have -B parameter we add its address
    if (multiAdrSet) {
      struct ip_mreq ip_mreq{};
      ip_mreq.imr_interface.s_addr = htonl(INADDR_ANY);
      if (inet_aton(multiAdr.c_str(), &ip_mreq.imr_multiaddr) == 0) {
        evacuate(SOCKUDP, false, "inet_aton – invalid multicast address");
      }

      if (setsockopt(socks[1].fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void*)&ip_mreq, sizeof ip_mreq) < 0) {
        evacuate(SOCKUDP, true, "setsockopt");
      }
    }

    struct sockaddr_in server_address{};
    server_address.sin_family = AF_INET; // IPv4
    server_address.sin_addr.s_addr = htonl(INADDR_ANY); // Listening on all interfaces
    server_address.sin_port = htons((short)stoi(cliPort)); // Default port for receiving is PORT_NUM

    if (bind(socks[1].fd, (struct sockaddr *) &server_address, (socklen_t) sizeof(server_address)) < 0) {
      evacuate(SOCKUDP, true, "bind UDP");
    }
  }

  // Creating a TCP socket
  socks[0].fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  socks[0].events = POLLIN;
  socks[0].revents = 0;

  if (socks[0].fd < 0) {
    evacuate(SOCKUDP, true, "socket TCP");
  }

  // We have to recognize server address
  memset(&addr_hints, 0, sizeof(struct addrinfo));
  addr_hints.ai_flags = 0;
  addr_hints.ai_family = AF_INET;
  addr_hints.ai_socktype = SOCK_STREAM;
  addr_hints.ai_protocol = IPPROTO_TCP;

  struct sockaddr_in server_address{};
  server_address.sin_family = AF_INET; // IPv4
  server_address.sin_addr.s_addr = htonl(INADDR_ANY); // listening on all interfaces
  server_address.sin_port = htons(0); // random port

  if (bind(socks[0].fd, (struct sockaddr *) &server_address, (socklen_t) sizeof(server_address)) < 0) {
    evacuate(SOCKTCP, true, "bind TCP");
  }

  if (getaddrinfo(hostname.c_str(), srcPort.c_str(), &addr_hints, &addr_result) != 0) {
    evacuate(SOCKTCP, false, "Address info error");
  }

  // Connecting with server
  if (connect(socks[0].fd, addr_result->ai_addr, addr_result->ai_addrlen) != 0) {
    if (mode != MODE_A)
      close(socks[1].fd);

    close(socks[0].fd);
    freeaddrinfo(addr_result);
    syserr("Connection error");
  }

  freeaddrinfo(addr_result);

  // Head
  string toSend = "GET " + resource + " HTTP/1.0\r\n";

  // Icy-MetaData
  if (requireMeta) {
    toSend += "Icy-MetaData:1\r\n";
  } else {
    toSend += "Icy-MetaData:0\r\n";
  }

  toSend += "\r\n";

  if (write(socks[0].fd, toSend.c_str(), toSend.length()) < 0) {
    evacuate(SOCKTCP, true, "Write error");
  }

  time_t sourceTime;

  time(&sourceTime);

  int readChars = 0;

  char readLine[BSIZE];

  // Trying to initialize a map
  try {
    listenMap = new map<unsigned long long, time_t>;
  } catch (...){
    evacuate(SOCKTCP, false, "Map creating exception");
  }

  // Receiving information and doing things according to this
  while (true) {
    int ret = poll(socks, THREAD_NUM, 1000 * sourceTimeout);

    if (ret == -1) {
      evacuate(SOCKTCP, true, "poll");
    }
    else {
      // Checks if timeout for source has gone
      if (difftime(time(nullptr), sourceTime) >= sourceTimeout) {
        catch_int(SIGINT);
        break;
      }
      if (socks[0].revents & POLLIN) {
        if ((readChars = read(socks[0].fd, readLine, BSIZE + 1)) < 0) {
          close(socks[0].fd);

          if (mode != MODE_A)
            close(socks[1].fd);

          delete listenMap;

          syserr("Read error");
        } else {
          serveLine(readLine, readChars);
        }

        time(&sourceTime);
      }

      int received;
      if (mode != MODE_A && socks[1].revents & POLLIN) {
        struct sockaddr_in src_addr;
        socklen_t addr_len = sizeof(src_addr);
        if ((received = recvfrom(socks[1].fd, readLine, CLIENT_SIZE + 1, 0, (struct sockaddr*)&src_addr/*nullptr*/, &addr_len)) < 0 ) {
          evacuate(ALL, true, "Read error");
        } else if (received >= 4){
          if (ntohs((uint16_t)((uint16_t*) readLine)[0]) == DISCOVER) {
            unsigned long long addrKey = portKey(src_addr);

            // Update or setting time and adding to client map
            if (listenMap->find(addrKey) == listenMap->end()) {
              if (!listenMap->emplace(addrKey, time(nullptr)).second) {
                evacuate(ALL, false, "Map emplace error");
              }
            } else {
              listenMap->at(addrKey) = time(nullptr);
            }

            // Sending IAM
            char komunikat[BSIZE+CLIENT_SIZE];
            *((uint16_t*) komunikat) = htons(IAM);
            *((uint16_t*) &komunikat[2]) = htons(nameLen);
            for (int i = 0; i < nameLen; i++) {
              komunikat[4 + i] = name[i];
            }

           sendto(socks[1].fd, komunikat, CLIENT_SIZE + nameLen, 0, (struct sockaddr*)&src_addr, addr_len);
          } else if (ntohs((uint16_t)((uint16_t*) readLine)[0]) == KEEPALIVE) {
            if (listenMap->find(portKey(src_addr)) != listenMap->end()) {
              // Updating time only if lower than timeout
              if (difftime(time(nullptr), listenMap->at(portKey(src_addr))) < clientTimeout)
                listenMap->at(portKey(src_addr)) = time(nullptr);
            }
          }
        }
      }
    }
  }

  return 0;
}
