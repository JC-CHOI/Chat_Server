
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sqlite3.h>
#include <crypt.h>

#define BUF_SIZE 100
#define MAX_CLNT 256

void *handle_client(void *arg);
void send_msg(char *msg, int len);
void error_handling(char *msg);

int verify_user(sqlite3 *db,int sock);
static int callback(void *data, int argc, char **argv, char **azColName);
int checkUser(sqlite3 *db, char *userId, char *password);


int clnt_cnt;
int clnt_socks[MAX_CLNT];
pthread_mutex_t mutx;

int main(int argc, char *argv[])
{
    int serv_sock, clnt_sock;
    struct sockaddr_in serv_adr, clnt_adr;
    int clnt_adr_sz;
    pthread_t t_id;
    sqlite3 *db;

    if( argc != 2)
    {
        printf("Usage : %s <port> \n",argv[0]);
        exit(1);
    }
    
    pthread_mutex_init(&mutx, NULL);
    serv_sock = socket(PF_INET, SOCK_STREAM, 0);

    memset(&serv_adr, 0, sizeof serv_adr);
    serv_adr.sin_family = AF_INET;
    serv_adr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_adr.sin_port = htons(atoi(argv[1]));

    if( bind( serv_sock, (struct sockaddr*) &serv_adr, sizeof(serv_adr)) == -1)
        error_handling("bind() error");
    if( listen(serv_sock, 5) == -1 )
        error_handling("listen() error");

    while(1)
    {
        clnt_adr_sz = sizeof clnt_adr;
        clnt_sock = accept(serv_sock, (struct sockaddr *)&clnt_adr, &clnt_adr_sz);
        
        if( !verify_user(db,clnt_sock) )
        {
            close(clnt_sock);
            continue;
        }
        pthread_mutex_lock(&mutx);
        clnt_socks[clnt_cnt++] = clnt_sock;
        pthread_mutex_unlock(&mutx);

        pthread_create(&t_id, NULL, handle_client, (void *)&clnt_sock);
        pthread_detach(t_id);
        printf("Connected client IP : %s\n",inet_ntoa(clnt_adr.sin_addr));
    }

    close(serv_sock);
    return 0;
}
int verify_user(sqlite3 *db, int client_sock)
{
    int str_len = 0, i;
    char msg[BUF_SIZE];
    char userID[20];
    char passwd[20];
    
    strcpy(msg,"Welcome chat server! ");
    write(client_sock, msg, strlen(msg));
    str_len = read(client_sock, userID, sizeof msg);
    
    strcpy(msg,"PassWord : ");
    write(client_sock, msg, strlen(msg));
    str_len = read(client_sock, passwd, sizeof passwd);
    //passwd[str_len-1] = '\0';
    if( checkUser(db, userID, passwd) )
    {
        strcpy(msg,"login passed \n");
        write(client_sock, msg, strlen(msg));
        return 1;
    }  
    else
    {
        strcpy(msg,"q");
        write(client_sock, msg, strlen(msg));
        close(client_sock);
        return 0;
    }
}

static int callback(void *data, int argc, char **argv, char **azColName) {
    int i;
    for (i = 0; i < argc; i++) {
        if( !strcmp(azColName[i],"passwd"))
            strcpy( (char *)data, argv[i]);
        //printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
    }
    
    return 0;
}

int checkUser(sqlite3 *db, char *name, char *passwd )
{
    char *errMsg=0;
    char query[256];
    const char *salt = "$5$thisissalt$";
    char *hashed = crypt(passwd, salt); 
    char pass[BUF_SIZE];

    if (sqlite3_open("example.db", &db) == SQLITE_OK)
    {
        if (sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS users (id INT, name TEXT,passwd TEXT);", 0, 0, &errMsg) != SQLITE_OK)
        {
            fprintf(stderr, "SQL error: %s\n", errMsg);
            sqlite3_free(errMsg);
        }
        else
        {
            snprintf(query, sizeof(query), "SELECT * FROM users WHERE name = '%s' ;", name);
            int result = sqlite3_exec(db, query, callback, pass, &errMsg);
            printf("pass : %s\n",pass);
            if (result != SQLITE_OK) {
                fprintf(stderr, "SQL error: %s\n", errMsg);
                sqlite3_free(errMsg);
            } else {
                if ( strcmp(pass, hashed) != 0 ) {
                    fprintf(stderr,"[%s]Login failed: User not found or password incorrect\n",name);
                    return 0;
                } else {
                    fprintf(stdout,"[%s]Login successful!\n",name);
                    return 1;
                }
            }
            printf("db open \n");
        }
            
    }
    else
    {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 0 ;
    }
}
void *handle_client(void *arg) // worker handler
{
    int clnt_sock = *((int *)arg);
    int str_len = 0, i;
    char msg[BUF_SIZE];

    while( (str_len = read(clnt_sock, msg, sizeof msg)) != 0)
        send_msg(msg, str_len);

    pthread_mutex_lock(&mutx);

    for( i=0; i<clnt_cnt; i++) // remove index
    {
        if( clnt_sock == clnt_socks[i])
        {
            while(i++ <clnt_cnt - 1)
                clnt_socks[i] = clnt_socks[i+1];
            break;
        }
    }
    clnt_cnt--;
    pthread_mutex_unlock(&mutx);
    close(clnt_sock);
    return NULL;
}
void send_msg(char *msg, int len)
{
    int i;
    pthread_mutex_lock(&mutx);
    for( i=0 ; i<clnt_cnt; i++)
    {
        write(clnt_socks[i], msg, len);
    }
    pthread_mutex_unlock(&mutx);
}

void error_handling(char *msg)
{
    fputs(msg, stderr);
    fputc('\n',stderr);
    exit(1);
}
