/* parser.h - Structures, functions and global variables for the */
/* tsocks parsing routines                                       */

#ifndef _PARSER_H
#define _PARSER_H

/* Structure definitions */

/* Structure representing a network */
struct networkent {
	struct in_addr localip; /* Base IP of the network */
	struct in_addr localnet; /* Mask for the network */
	unsigned long startport; /* Range of ports for the */
	unsigned long endport;   /* network                */
	struct networkent *next; /* Pointer to next network entry */
};

/* Structure representing one server specified in the config */
struct serverent {
	int lineno; /* Line number in conf file this path started on */
	char *address; /* Address/hostname of server */
	int port; /* Port number of server */
	int type; /* Type of server (4/5) */
	char *defuser; /* Default username for this socks server */
	char *defpass; /* Default password for this socks server */
	struct networkent *reachnets; /* Linked list of nets from this server */
	struct serverent *next; /* Pointer to next server entry */
};

/* Structure representing a complete parsed file */
struct parsedfile {
   struct networkent *localnets;
   struct serverent defaultserver;
   struct serverent *paths;
};

/* Functions provided by parser module */
int read_config(char *, struct parsedfile *);
int is_local(struct parsedfile *, struct in_addr *);
int pick_server(struct parsedfile *, struct serverent **, struct in_addr *, unsigned int port, int startindex);
int free_config(struct parsedfile *config);
int list_servers(struct parsedfile *config, char ***argv);

#endif
