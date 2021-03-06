/* TinyScheme Extensions
 * (c) 2002 Visual Tools, S.A.
 * Manuel Heras-Gilsanz (manuel@heras-gilsanz.com)
 *
 * This software is subject to the terms stated in the
 * LICENSE file.
 */

#include "scheme-private.h"
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <dirent.h>
#include "tsx.h"

#undef cons

#ifdef HAVE_MISC
pointer foreign_getenv(scheme * sc, pointer args)
{
  pointer first_arg;
  pointer ret;
  char * varname;
  char * value;

  if(args == sc->NIL)
  {
    return sc->F;
  }

  first_arg = sc->vptr->pair_car(args);

  if(!sc->vptr->is_string(first_arg))
  {
    return sc->F;
  }

  varname = sc->vptr->string_value(first_arg);
  value = getenv(varname);
  if (0 == value)
  {
    ret = sc->F;
  }
  else
  {
    ret = sc->vptr->mk_string(sc,value);
  }
  return ret;
}

pointer foreign_system(scheme * sc, pointer args)
{
  pointer first_arg;
  char * command;
  int retcode;

  if(args == sc->NIL)
    return sc->F;

  first_arg = sc->vptr->pair_car(args);
  if(!sc->vptr->is_string(first_arg))
    return sc->F;

  command = sc->vptr->string_value(first_arg);
  if(0 == command)
    return sc->F;

  retcode = system(command);
  if( (127 == retcode) || (-1 == retcode) )
    return sc->F;

  return (sc->vptr->mk_integer(sc,retcode));
}
#endif /* defined (HAVE_MISC) */

#ifdef HAVE_FILESYSTEM
pointer foreign_filesize(scheme * sc, pointer args)
{
  pointer first_arg;
  pointer ret;
  struct stat buf;
  char * filename;
  int retcode;

  if(args == sc->NIL)
    return sc->F;

  first_arg = sc->vptr->pair_car(args);
  if(!sc->vptr->is_string(first_arg)) {
    return sc->F;
  }

  filename = sc->vptr->string_value(first_arg);
  retcode = stat(filename, &buf);
  if (0 == retcode)
  {
    ret = sc->vptr->mk_integer(sc,buf.st_size);
  }
  else
  {
    ret = sc->F;
  }
  return ret;
}

pointer foreign_fileexists(scheme * sc, pointer args)
{
  pointer first_arg;
  pointer ret;
  struct stat buf;
  char * filename;
  int retcode;

  if(args == sc->NIL)
    return sc->F;

  first_arg = sc->vptr->pair_car(args);
  if(!sc->vptr->is_string(first_arg)) {
    return sc->F;
  }

  filename = sc->vptr->string_value(first_arg);
  retcode = stat(filename, &buf);
  if (0 == retcode)
  {
    ret = sc->T;
  }
  else
  {
    ret = sc->F;
  }
  return ret;
}

pointer foreign_deletefile(scheme * sc, pointer args)
{
  pointer first_arg;
  pointer ret;
  char * filename;
  int retcode;

  if(args == sc->NIL)
    return sc->F;

  first_arg = sc->vptr->pair_car(args);
  if(!sc->vptr->is_string(first_arg)) {
    return sc->F;
  }

  filename = sc->vptr->string_value(first_arg);
  retcode = unlink(filename);
  if (0 == retcode) {
    ret = sc->T;
  }
  else {
    ret = sc->F;
  }
  return ret;
}

pointer foreign_opendirstream(scheme * sc, pointer args)
{
  pointer first_arg;
  char * dirpath;
  DIR * dir;

  if(args == sc->NIL)
    return sc->F;

  first_arg = sc->vptr->pair_car(args);
  if(!sc->vptr->is_string(first_arg))
    return sc->F;

  dirpath = sc->vptr->string_value(first_arg);

  dir = opendir(dirpath);
  if(0 == dir)
    return sc->F;

  return (sc->vptr->mk_integer(sc,(int) dir));
}

pointer foreign_readdirentry(scheme * sc, pointer args)
{
  pointer first_arg;
  DIR * dir;
  struct dirent * entry;

  if(args == sc->NIL)
    return sc->F;

  first_arg = sc->vptr->pair_car(args);
  if(!sc->vptr->is_number(first_arg))
    return sc->F;

  dir = (DIR *) sc->vptr->ivalue(first_arg);
  if(0 == dir)
    return sc->F;

  entry = readdir(dir);
  if(0 == entry)
    return sc->EOF_OBJ;

  return (sc->vptr->mk_string(sc,entry->d_name));
}

pointer foreign_closedirstream(scheme * sc, pointer args)
{
  pointer first_arg;
  DIR * dir;

  if(args == sc->NIL)
    return sc->F;

  first_arg = sc->vptr->pair_car(args);
  if(!sc->vptr->is_number(first_arg))
    return sc->F;

  dir = (DIR *) sc->vptr->ivalue(first_arg);
  if(0 == dir)
    return sc->F;

  closedir(dir);
  return sc->T;
}
#endif /* defined (HAVE_FILESYSTEM) */

#ifdef HAVE_TIME
pointer foreign_time(scheme * sc, pointer args)
{
  time_t now;
  struct tm * now_tm;
  pointer ret;

  if(args != sc->NIL)
  {
    return sc->F;
  }

  time(&now);
  now_tm = localtime(&now);

  ret = sc->vptr->cons(sc,sc->vptr->mk_integer(sc,(long) now_tm->tm_year),
      sc->vptr->cons(sc,sc->vptr->mk_integer(sc,(long) now_tm->tm_mon),
        sc->vptr->cons(sc,sc->vptr->mk_integer(sc,(long) now_tm->tm_mday),
          sc->vptr->cons(sc,sc->vptr->mk_integer(sc,(long) now_tm->tm_hour),
            sc->vptr->cons(sc,sc->vptr->mk_integer(sc,(long) now_tm->tm_min),
              sc->vptr->cons(sc,sc->vptr->mk_integer(sc,(long) now_tm->tm_sec),sc->NIL))))));

  return ret;
}

pointer foreign_gettimeofday(scheme * sc, pointer args)
{
  struct timeval tv;
  pointer ret;

  gettimeofday(&tv, 0);

  ret = sc->vptr->cons(sc,sc->vptr->mk_integer(sc,(long) tv.tv_sec),
      sc->vptr->cons(sc,sc->vptr->mk_integer(sc,(long) tv.tv_usec),
        sc->NIL));

  return ret;
}

pointer foreign_usleep(scheme * sc, pointer args)
{
  pointer first_arg;
  long usec;

  if(args == sc->NIL)
    return sc->F;

  first_arg = sc->vptr->pair_car(args);
  if(!sc->vptr->is_integer(first_arg)) {
    return sc->F;
  }

  usec = sc->vptr->ivalue(first_arg);
  usleep(usec);

  return sc->T;
}
#endif /* defined (HAVE_TIME) */

#ifdef HAVE_SOCKETS
pointer foreign_makeclientsocket(scheme * sc, pointer args)
{
  pointer first_arg;
  pointer second_arg;
  pointer ret;
  struct sockaddr_in address;
  struct in_addr inaddr;
  struct hostent * host;
  char * hostname;
  int retcode;
  long port;
  int sock;

  if(args == sc->NIL)
    return sc->F;

  first_arg = sc->vptr->pair_car(args);
  if(!sc->vptr->is_string(first_arg)) {
    return sc->F;
  }
  args = sc->vptr->pair_cdr(args);
  second_arg = sc->vptr->pair_car(args);
  if(!sc->vptr->is_number(second_arg)) {
    return sc->F;
  }

  hostname = sc->vptr->string_value(first_arg);
  port = sc->vptr->ivalue(second_arg);

  if(inet_aton(hostname, &inaddr))
    host = gethostbyaddr((char *) &inaddr, sizeof(inaddr), AF_INET);
  else
    host = gethostbyname(hostname);

  if(0 == host) {
    return sc->F;
  }

  sock = socket(PF_INET, SOCK_STREAM, 0);
  if(-1==sock) {
    return sc->F;
  }

  address.sin_family = AF_INET;
  address.sin_port   = htons(port);
  memcpy(&address.sin_addr, host->h_addr_list[0], sizeof(address.sin_addr));

  retcode = connect(sock, (struct sockaddr *)&address, sizeof(address));
  if (0 == retcode) {
    ret = sc->vptr->mk_integer(sc,sock);
  }
  else {
    ret = sc->F;
  }
  return ret;
}

pointer foreign_makeserversocket(scheme * sc, pointer args)
{
  pointer first_arg;
  struct sockaddr_in address;
  long port;
  int one = 1;
  int sock;

  if(args == sc->NIL)
    return sc->F;

  first_arg = sc->vptr->pair_car(args);
  if(!sc->vptr->is_number(first_arg)) {
    return sc->F;
  }

  port = sc->vptr->ivalue(first_arg);

  sock = socket(PF_INET, SOCK_STREAM, 0);
  if(-1==sock) {
    return sc->F;
  }

  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

  address.sin_family = AF_INET;
  address.sin_port   = htons(port);
  memset(&address.sin_addr, 0, sizeof(address.sin_addr));

  if(bind(sock, (struct sockaddr *) &address, sizeof(address))) {
    return sc->F;
  }

  if(listen(sock, 1)) {
    return sc->F;
  }

  return (sc->vptr->mk_integer(sc,sock));
}

pointer foreign_recv(scheme * sc, pointer args)
{
  pointer first_arg;
  pointer second_arg;
  int sock;
  char * buf;
  pointer ret;
  int retcode;

  if(args == sc->NIL)
    return sc->F;

  first_arg = sc->vptr->pair_car(args);
  if(!sc->vptr->is_number(first_arg)) {
    return sc->F;
  }
  args = sc->vptr->pair_cdr(args);
  second_arg = sc->vptr->pair_car(args);
  if(!sc->vptr->is_string(second_arg)) {
    return sc->F;
  }

  sock = sc->vptr->ivalue(first_arg);
  buf  = sc->vptr->string_value(second_arg);

  retcode = recv(sock, buf, strlen(buf), 0);
  if (-1 == retcode) {
    ret = sc->F;
  }
  else {
    ret = sc->vptr->mk_integer(sc,retcode);
  }

  return ret;
}

pointer foreign_recvnewbuf(scheme * sc, pointer args)
{
  pointer first_arg;
  int sock;
  pointer ret;
  int lenreceived;
  char buf[2500];

  if(args == sc->NIL) return sc->F;

  first_arg = sc->vptr->pair_car(args);
  if(!sc->vptr->is_number(first_arg)) return sc->F;

  sock = sc->vptr->ivalue(first_arg);

  lenreceived = recv(sock, buf, sizeof(buf) - 1, 0);
  if (-1 == lenreceived) return sc->F;

  buf[lenreceived] = 0;
  ret = sc->vptr->mk_string(sc,buf);

  return ret;
}

pointer foreign_isdataready(scheme * sc, pointer args)
{
  pointer first_arg;
  int sock;
  struct timeval tv;
  fd_set fds;
  fd_set fdsin;

  if(args == sc->NIL) return sc->F;

  first_arg = sc->vptr->pair_car(args);
  if(!sc->vptr->is_number(first_arg)) return sc->F;

  sock = sc->vptr->ivalue(first_arg);

  tv.tv_sec = 0;
  tv.tv_usec = 0;

  FD_ZERO(&fds);
  FD_SET(sock, &fds);
  fdsin = fds;
  if (select(1+sock, &fdsin, NULL, NULL, &tv) < 0)
  {
    return sc->F;
  }
  if (FD_ISSET(sock, &fdsin))
    return sc->T;
  return sc->F;
}

pointer foreign_sockpeek(scheme * sc, pointer args)
{
  pointer first_arg;
  int sock;
  pointer ret;
  int lenreceived;
  char buf[2500];

  if(args == sc->NIL) return sc->F;

  first_arg = sc->vptr->pair_car(args);
  if(!sc->vptr->is_number(first_arg)) return sc->F;

  sock = sc->vptr->ivalue(first_arg);

  lenreceived = recv(sock, buf, sizeof(buf) - 1, MSG_PEEK);
  if (-1 == lenreceived) return sc->F;

  buf[lenreceived] = 0;
  ret = sc->vptr->mk_string(sc,buf);

  return ret;
}

pointer foreign_send(scheme * sc, pointer args)
{
  pointer first_arg;
  pointer second_arg;
  int sock;
  char * buf;
  pointer ret;
  int retcode;

  if(args == sc->NIL)
    return sc->F;

  first_arg = sc->vptr->pair_car(args);
  if(!sc->vptr->is_number(first_arg)) {
    return sc->F;
  }
  args = sc->vptr->pair_cdr(args);
  second_arg = sc->vptr->pair_car(args);
  if(!sc->vptr->is_string(second_arg)) {
    return sc->F;
  }

  sock = sc->vptr->ivalue(first_arg);
  buf  = sc->vptr->string_value(second_arg);

  retcode = send(sock, buf, strlen(buf), 0);
  if (-1 == retcode) {
    ret = sc->F;
  }
  else {
    ret = sc->vptr->mk_integer(sc,retcode);
  }

  return ret;
}

pointer foreign_accept(scheme * sc, pointer args)
{
  pointer first_arg;
  int sock;
  struct sockaddr_in addr;
  pointer ret;
  socklen_t addr_len = sizeof(struct sockaddr_in);
  int retcode;

  if(args == sc->NIL)
    return sc->F;

  first_arg = sc->vptr->pair_car(args);
  if(!sc->vptr->is_number(first_arg)) {
    return sc->F;
  }

  sock = sc->vptr->ivalue(first_arg);

  retcode = accept(sock, (struct sockaddr *)&addr, &addr_len);
  if (-1 == retcode) {
    ret = sc->F;
  }
  else {
    ret = sc->vptr->mk_integer(sc,retcode);
  }

  return ret;
}

pointer foreign_closesocket(scheme * sc, pointer args)
{
  pointer first_arg;
  int sock;
  int retcode;

  if(args == sc->NIL)
    return sc->F;

  first_arg = sc->vptr->pair_car(args);
  if(!sc->vptr->is_number(first_arg))
    return sc->F;

  sock = sc->vptr->ivalue(first_arg);

  retcode = close(sock);
  if (-1 == retcode)
    return sc->F;

  return sc->T;
}
#endif /* defined (HAVE_SOCKETS) */

#ifdef HAVE_SQLITE
#include <sqlite3.h>

#ifdef __LP64__
#define ptr long
#else
#define ptr int
#endif

pointer foreign_sqliteopen(scheme * sc, pointer args) {
  sqlite3 *sqlite;
  pointer first_arg;
  int retcode;

  if(args == sc->NIL)
    return sc->F;

  first_arg = sc->vptr->pair_car(args);
  if(!sc->vptr->is_string(first_arg))
    return sc->F;

  retcode = sqlite3_open(sc->vptr->string_value(first_arg), &sqlite);
  if (retcode == -1)
    return sc->F;

  return sc->vptr->mk_integer(sc, (ptr)sqlite);
}

pointer foreign_sqliteprepare(scheme * sc, pointer args) {
  pointer first_arg;
  pointer second_arg;
  int retcode;

  if(args == sc->NIL)
    return sc->F;

  first_arg = sc->vptr->pair_car(args);
  if(!sc->vptr->is_number(first_arg))
    return sc->F;

  args = sc->vptr->pair_cdr(args);
  second_arg = sc->vptr->pair_car(args);
  if(!sc->vptr->is_string(second_arg))
    return sc->F;

  sqlite3_stmt *stmt;
  retcode = sqlite3_prepare((sqlite3*)sc->vptr->ivalue(first_arg), 
      sc->vptr->string_value(second_arg), 
      -1, &stmt, (const char **)NULL);

  if(retcode != SQLITE_OK)
    return sc->F;

  return sc->vptr->mk_integer(sc, (ptr)stmt);
}

pointer foreign_sqlitebindtext(scheme * sc, pointer args) {
  pointer first_arg, second_arg, third_arg;
  int retcode;

  if(args == sc->NIL)
    return sc->F;

  first_arg = sc->vptr->pair_car(args);
  if(!sc->vptr->is_number(first_arg))
    return sc->F;

  args = sc->vptr->pair_cdr(args);
  second_arg = sc->vptr->pair_car(args);
  if(!sc->vptr->is_number(second_arg))
    return sc->F;

  args = sc->vptr->pair_cdr(args);
  third_arg = sc->vptr->pair_car(args);
  if(!sc->vptr->is_string(third_arg))
    return sc->F;

  retcode = sqlite3_bind_text(
      (sqlite3_stmt*)sc->vptr->ivalue(first_arg), 
      sc->vptr->ivalue(second_arg), 
      sc->vptr->string_value(third_arg), 
      -1, SQLITE_STATIC);

  if(retcode != SQLITE_OK) {
    printf("retcode: %d\n", retcode);
    return sc->F;
  }

  return sc->T;
}

pointer foreign_sqlitebindblob(scheme * sc, pointer args) {
  pointer first_arg, second_arg, third_arg;
  int retcode;

  if(args == sc->NIL)
    return sc->F;

  first_arg = sc->vptr->pair_car(args);
  if(!sc->vptr->is_number(first_arg))
    return sc->F;

  args = sc->vptr->pair_cdr(args);
  second_arg = sc->vptr->pair_car(args);
  if(!sc->vptr->is_number(second_arg))
    return sc->F;

  args = sc->vptr->pair_cdr(args);
  third_arg = sc->vptr->pair_car(args);
  if(!sc->vptr->is_blob(third_arg))
    return sc->F;

  retcode = sqlite3_bind_blob(
      (sqlite3_stmt*)sc->vptr->ivalue(first_arg),
      sc->vptr->ivalue(second_arg),
      sc->vptr->blob_value(third_arg),
      sc->vptr->blob_size(third_arg), SQLITE_STATIC);

  if(retcode != SQLITE_OK) {
    printf("retcode: %d\n", retcode);
    return sc->F;
  }

  return sc->T;
}

pointer foreign_sqlitestep(scheme * sc, pointer args) {
  pointer first_arg;
  int retcode;

  if(args == sc->NIL)
    return sc->F;

  first_arg = sc->vptr->pair_car(args);
  if(!sc->vptr->is_number(first_arg))
    return sc->F;

  retcode = sqlite3_step((sqlite3_stmt*)sc->vptr->ivalue(first_arg));
  if(retcode != SQLITE_DONE && retcode != SQLITE_ROW)
    return sc->F;

  return sc->T;
}

pointer foreign_sqlitefinalize(scheme * sc, pointer args) {
  pointer first_arg;
  int retcode;

  if (args == sc->NIL)
    return sc->F;

  first_arg = sc->vptr->pair_car(args);
  if(!sc->vptr->is_number(first_arg))
    return sc->F;

  retcode = sqlite3_finalize((sqlite3_stmt*)sc->vptr->ivalue(first_arg));
  if(SQLITE_OK != retcode)
    return sc->F;

  return sc->T;
}

pointer foreign_sqlitereset(scheme * sc, pointer args) {
  pointer first_arg;
  int retcode;

  if (args == sc->NIL)
    return sc->F;

  first_arg = sc->vptr->pair_car(args);
  if(!sc->vptr->is_number(first_arg))
    return sc->F;

  retcode = sqlite3_reset((sqlite3_stmt*)sc->vptr->ivalue(first_arg));
  if(SQLITE_OK != retcode)
    return sc->F;

  return sc->T;
}

pointer foreign_sqliteclearbindings(scheme * sc, pointer args) {
  pointer first_arg;
  int retcode;

  if (args == sc->NIL)
    return sc->F;

  first_arg = sc->vptr->pair_car(args);
  if(!sc->vptr->is_number(first_arg))
    return sc->F;

  retcode = sqlite3_clear_bindings((sqlite3_stmt*)sc->vptr->ivalue(first_arg));
  if(SQLITE_OK != retcode)
    return sc->F;

  return sc->T;
}

pointer foreign_sqlitecolumntext(scheme * sc, pointer args) {
  pointer first_arg;
  pointer second_arg;
  char *ret;

  if(args == sc->NIL)
    return sc->F;

  first_arg = sc->vptr->pair_car(args);
  if(!sc->vptr->is_number(first_arg))
    return sc->F;

  args = sc->vptr->pair_cdr(args);
  second_arg = sc->vptr->pair_car(args);
  if(!sc->vptr->is_number(second_arg))
    return sc->F;

  ret = sqlite3_column_text((sqlite3_stmt*)sc->vptr->ivalue(first_arg), 
      sc->vptr->ivalue(second_arg));

  if (ret == NULL)
    return sc->F;

  return sc->vptr->mk_string(sc, ret);
}

pointer foreign_sqlitecolumnblob(scheme * sc, pointer args) {
  pointer first_arg;
  pointer second_arg;
  char *ret;
  int len;

  if(args == sc->NIL)
    return sc->F;

  first_arg = sc->vptr->pair_car(args);
  if(!sc->vptr->is_number(first_arg))
    return sc->F;

  args = sc->vptr->pair_cdr(args);
  second_arg = sc->vptr->pair_car(args);
  if(!sc->vptr->is_number(second_arg))
    return sc->F;

  ret = sqlite3_column_blob((sqlite3_stmt*)sc->vptr->ivalue(first_arg), 
      sc->vptr->ivalue(second_arg));

  len = sqlite3_column_bytes((sqlite3_stmt*)sc->vptr->ivalue(first_arg),
      sc->vptr->ivalue(second_arg));

  if (ret == NULL)
    return sc->F;

  return sc->vptr->mk_blob(sc, ret, len);
}

pointer foreign_sqliteclose(scheme * sc, pointer args) {
  pointer first_arg;
  if(args == sc->NIL)
    return sc->F;

  first_arg = sc->vptr->pair_car(args);
  if(!sc->vptr->is_number(first_arg))
    return sc->F;

  sqlite3 *sqlite = sc->vptr->ivalue(first_arg);
  sqlite3_stmt *pStmt;
  while((pStmt = sqlite3_next_stmt(sqlite, 0)) != 0 ) {
    sqlite3_finalize(pStmt);
  }

  sqlite3_close(sqlite);
  return sc->T;
}
#endif /* defined (HAVE_SQLITE) */
#ifdef HAVE_ECIES
#include "ecc.h"

pointer foreign_eciesinit(scheme * sc, pointer args) {
  ECIES_init();
  return sc->T;
}

pointer foreign_ecieskeypair(scheme * sc, pointer args) {
  char buf[8 * NUMWORDS + 1], *bufptr = buf + NUMWORDS * 8 - (DEGREE + 3) / 4;
  elem_t x, y;
  exp_t k;
  get_random_exponent(k);
  point_copy(x, y, base_x, base_y);
  point_mult(x, y, k);

  char public_x[1024];
  bitstr_to_hex(buf, x); sprintf(public_x, "%s", bufptr);

  char public_y[1024];
  bitstr_to_hex(buf, y); sprintf(public_y, "%s", bufptr);

  char private[1024];
  bitstr_to_hex(buf, k); sprintf(private, "%s", bufptr);

  pointer ret = sc->vptr->mk_vector(sc, 3);
  sc->vptr->set_vector_elem(ret, 0, sc->vptr->mk_string(sc, public_x));
  sc->vptr->set_vector_elem(ret, 1, sc->vptr->mk_string(sc, public_y));
  sc->vptr->set_vector_elem(ret, 2, sc->vptr->mk_string(sc, private));

  return ret;
}

pointer foreign_eciesencryption(scheme * sc, pointer args) {
  pointer first_arg;
  pointer second_arg;
  pointer third_arg;
  if(args == sc->NIL)
    return sc->F;

  first_arg = sc->vptr->pair_car(args);
  if(!sc->vptr->is_string(first_arg))
    return sc->F;

  args = sc->vptr->pair_cdr(args);
  second_arg = sc->vptr->pair_car(args);
  if(!sc->vptr->is_string(second_arg))
    return sc->F;

  args = sc->vptr->pair_cdr(args);
  third_arg = sc->vptr->pair_car(args);
  if(!sc->vptr->is_string(third_arg))
    return sc->F;

  char *text = sc->vptr->string_value(first_arg);
  int len = strlen(text) + 1;
  char *public_x = sc->vptr->string_value(second_arg);
  char *public_y = sc->vptr->string_value(third_arg);
  pointer ret = sc->vptr->mk_blob(sc, 0, len + ECIES_OVERHEAD);
  char *encrypted = sc->vptr->blob_value(ret);
  ECIES_encryption(encrypted, text, len, public_x, public_y);
  return ret;
}

pointer foreign_eciesdecryption(scheme * sc, pointer args) {
  pointer first_arg;
  pointer second_arg;
  int retcode;

  if(args == sc->NIL)
    return sc->F;

  first_arg = sc->vptr->pair_car(args);
  if(!sc->vptr->is_blob(first_arg))
    return sc->F;

  args = sc->vptr->pair_cdr(args);
  second_arg = sc->vptr->pair_car(args);
  if(!sc->vptr->is_string(second_arg))
    return sc->F;

  char *encrypted = sc->vptr->blob_value(first_arg);
  int len = sc->vptr->blob_size(first_arg) - ECIES_OVERHEAD;
  char *private = sc->vptr->string_value(second_arg);
  pointer ret = sc->vptr->mk_counted_string(sc, 0, len);
  char *decrypted = sc->vptr->string_value(ret);
  retcode = ECIES_decryption(decrypted, encrypted, len, private);
  if (retcode < 0) {
    printf("private: %s\n", private);
    printf("encrypted size: %d\n", sc->vptr->blob_size(first_arg));
    return sc->F;
  }

  return ret;
}

#endif /* defined (HAVE_ECIES) */

/* This function gets called when TinyScheme is loading the extension */
void init_tsx (scheme * sc)
{
#ifdef HAVE_MISC
  sc->vptr->scheme_define(sc,sc->global_env,
      sc->vptr->mk_symbol(sc,"getenv"),
      sc->vptr->mk_foreign_func(sc, foreign_getenv));
  sc->vptr->scheme_define(sc,sc->global_env,
      sc->vptr->mk_symbol(sc,"system"),
      sc->vptr->mk_foreign_func(sc, foreign_system));
#endif /* defined (HAVE_MISC) */
#ifdef HAVE_TIME
  sc->vptr->scheme_define(sc,sc->global_env,
      sc->vptr->mk_symbol(sc,"time"),
      sc->vptr->mk_foreign_func(sc, foreign_time));
  sc->vptr->scheme_define(sc,sc->global_env,
      sc->vptr->mk_symbol(sc,"gettimeofday"),
      sc->vptr->mk_foreign_func(sc, foreign_gettimeofday));
  sc->vptr->scheme_define(sc,sc->global_env,
      sc->vptr->mk_symbol(sc,"usleep"),
      sc->vptr->mk_foreign_func(sc, foreign_usleep));
#endif /* defined (HAVE_TIME) */
#ifdef HAVE_FILESYSTEM
  sc->vptr->scheme_define(sc,sc->global_env,
      sc->vptr->mk_symbol(sc,"file-size"),
      sc->vptr->mk_foreign_func(sc, foreign_filesize));
  sc->vptr->scheme_define(sc,sc->global_env,
      sc->vptr->mk_symbol(sc,"file-exists?"),
      sc->vptr->mk_foreign_func(sc, foreign_fileexists));
  sc->vptr->scheme_define(sc,sc->global_env,
      sc->vptr->mk_symbol(sc,"delete-file"),
      sc->vptr->mk_foreign_func(sc, foreign_deletefile));
  sc->vptr->scheme_define(sc,sc->global_env,
      sc->vptr->mk_symbol(sc,"open-dir-stream"),
      sc->vptr->mk_foreign_func(sc, foreign_opendirstream));
  sc->vptr->scheme_define(sc,sc->global_env,
      sc->vptr->mk_symbol(sc,"read-dir-entry"),
      sc->vptr->mk_foreign_func(sc, foreign_readdirentry));
  sc->vptr->scheme_define(sc,sc->global_env,
      sc->vptr->mk_symbol(sc,"close-dir-stream"),
      sc->vptr->mk_foreign_func(sc, foreign_closedirstream));
#endif /* defined (HAVE_FILESYSTEM) */
#ifdef HAVE_SOCKETS
  sc->vptr->scheme_define(sc,sc->global_env,
      sc->vptr->mk_symbol(sc,"make-client-socket"),
      sc->vptr->mk_foreign_func(sc, foreign_makeclientsocket));
  sc->vptr->scheme_define(sc,sc->global_env,
      sc->vptr->mk_symbol(sc,"make-server-socket"),
      sc->vptr->mk_foreign_func(sc, foreign_makeserversocket));
  sc->vptr->scheme_define(sc,sc->global_env,
      sc->vptr->mk_symbol(sc,"recv!"),
      sc->vptr->mk_foreign_func(sc, foreign_recv));
  sc->vptr->scheme_define(sc,sc->global_env,
      sc->vptr->mk_symbol(sc,"recv-new-string"),
      sc->vptr->mk_foreign_func(sc, foreign_recvnewbuf));
  sc->vptr->scheme_define(sc,sc->global_env,
      sc->vptr->mk_symbol(sc,"sock-peek"),
      sc->vptr->mk_foreign_func(sc, foreign_sockpeek));
  sc->vptr->scheme_define(sc,sc->global_env,
      sc->vptr->mk_symbol(sc,"sock-is-data-ready?"),
      sc->vptr->mk_foreign_func(sc, foreign_isdataready));
  sc->vptr->scheme_define(sc,sc->global_env,
      sc->vptr->mk_symbol(sc,"send"),
      sc->vptr->mk_foreign_func(sc, foreign_send));
  sc->vptr->scheme_define(sc,sc->global_env,
      sc->vptr->mk_symbol(sc,"accept"),
      sc->vptr->mk_foreign_func(sc, foreign_accept));
  sc->vptr->scheme_define(sc,sc->global_env,
      sc->vptr->mk_symbol(sc,"close-socket"),
      sc->vptr->mk_foreign_func(sc, foreign_closesocket));
#endif /* defined (HAVE_SOCKETS) */
#ifdef HAVE_SQLITE
  sc->vptr->scheme_define(sc, sc->global_env,
      sc->vptr->mk_symbol(sc, "sqlite-open"),
      sc->vptr->mk_foreign_func(sc, foreign_sqliteopen));
  sc->vptr->scheme_define(sc, sc->global_env,
      sc->vptr->mk_symbol(sc, "sqlite-prepare"),
      sc->vptr->mk_foreign_func(sc, foreign_sqliteprepare));
  sc->vptr->scheme_define(sc, sc->global_env,
      sc->vptr->mk_symbol(sc, "sqlite-bind-text"),
      sc->vptr->mk_foreign_func(sc, foreign_sqlitebindtext));
  sc->vptr->scheme_define(sc, sc->global_env,
      sc->vptr->mk_symbol(sc, "sqlite-bind-blob"),
      sc->vptr->mk_foreign_func(sc, foreign_sqlitebindblob));
  sc->vptr->scheme_define(sc, sc->global_env,
      sc->vptr->mk_symbol(sc, "sqlite-step"),
      sc->vptr->mk_foreign_func(sc, foreign_sqlitestep));
  sc->vptr->scheme_define(sc, sc->global_env,
      sc->vptr->mk_symbol(sc, "sqlite-finalize"),
      sc->vptr->mk_foreign_func(sc, foreign_sqlitefinalize));
  sc->vptr->scheme_define(sc, sc->global_env,
      sc->vptr->mk_symbol(sc, "sqlite-reset"),
      sc->vptr->mk_foreign_func(sc, foreign_sqlitereset));
  sc->vptr->scheme_define(sc, sc->global_env,
      sc->vptr->mk_symbol(sc, "sqlite-clear-bindings"),
      sc->vptr->mk_foreign_func(sc, foreign_sqliteclearbindings));
  sc->vptr->scheme_define(sc, sc->global_env,
      sc->vptr->mk_symbol(sc, "sqlite-column-text"),
      sc->vptr->mk_foreign_func(sc, foreign_sqlitecolumntext));
  sc->vptr->scheme_define(sc, sc->global_env,
      sc->vptr->mk_symbol(sc, "sqlite-column-blob"),
      sc->vptr->mk_foreign_func(sc, foreign_sqlitecolumnblob));
  sc->vptr->scheme_define(sc, sc->global_env,
      sc->vptr->mk_symbol(sc, "sqlite-close"),
      sc->vptr->mk_foreign_func(sc, foreign_sqliteclose));
#endif /* defined (HAVE_SQLITE) */
#ifdef HAVE_ECIES
  sc->vptr->scheme_define(sc, sc->global_env,
      sc->vptr->mk_symbol(sc, "ecies-init"),
      sc->vptr->mk_foreign_func(sc, foreign_eciesinit));
  sc->vptr->scheme_define(sc, sc->global_env,
      sc->vptr->mk_symbol(sc, "ecies-keypair"),
      sc->vptr->mk_foreign_func(sc, foreign_ecieskeypair));
  sc->vptr->scheme_define(sc, sc->global_env,
      sc->vptr->mk_symbol(sc, "ecies-encryption"),
      sc->vptr->mk_foreign_func(sc, foreign_eciesencryption));
  sc->vptr->scheme_define(sc, sc->global_env,
      sc->vptr->mk_symbol(sc, "ecies-decryption"),
      sc->vptr->mk_foreign_func(sc, foreign_eciesdecryption));
#endif /* defined (HAVE_ECIES) */
}
