#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>
#include <ctype.h>
#include "frontier_client/frontier.h"

#define RESULT_TYPE_ARRAY 6
#define RESULT_TYPE_EOR 7

char *
doubleurlencode(char *frombuf)
 {
  int c,n;
  char *tobuf=malloc(strlen(frombuf)*5+1);
  char *p=tobuf;
  while((c=*frombuf++)!=0)
   {
    if(isalnum(c)||(c=='/')||(c=='-')||(c=='_')||(c=='.'))
      *p++=c;
    else
     {
      // %25 is the encoding of %
      *p++='%';
      *p++='2';
      *p++='5';
      n=(c>>4);
      if(n<10)
        *p++=n+'0';
      else
        *p++=n-10+'a';
      n=(c&0xf);
      if(n<10)
        *p++=n+'0';
      else
        *p++=n-10+'a';
     }
   }
  *p='\0';
  return tobuf;
 }

struct statestruct
 {
  FrontierRSBlob *frsb;
  char *buff;
 };

//changed char *connectstr to const char *connectstr
int frontierretrieve(void **state,unsigned long *statelong,const char *connectstr,char *query,char **buff) //rename main to frontierretrieve
 {
  int ec,c,i;
  unsigned long channel;
  int ttl=2;
  int ziplevel=0;
  char zipstr[5];
  FrontierConfig *config;
  //const char *connectstr="";//changing to const char isntead of char


//  while(1)
//   {
//    c=getopt(argc,argv,":c:rR");
//    switch(c)
//     {
//      case 'c':
//        connectstr=optarg;
//        break;
//      case 'r':
//        ttl=1;
//        break;
//      case 'R':
//        ttl=3;
//        break;
//      case -1:
//        break;
//      case ':':
//        fprintf(stderr,"Missing argument\n");
//        usage();
//      default:
//        fprintf(stderr,"Unrecognized option\n");
//        usage();
//     }
//   if(c==-1)
//      break;
//   }
//  if(optind>=argc)
//   {
//    fprintf(stderr,"No files requested\n");
//    usage();
//   }
  /* default zip level to 0, unlike ordinary frontier client */
  if(getenv("FRONTIER_RETRIEVEZIPLEVEL")==0)
    putenv("FRONTIER_RETRIEVEZIPLEVEL=0");

  if(frontier_init(malloc,free)!=0)
   {
    fprintf(stderr,"Error initializing frontier client: %s\n",frontier_getErrorMsg());
    return 2;
   }
  ec=FRONTIER_OK;
  config=frontierConfig_get(connectstr,"",&ec); 

  if(ec!=FRONTIER_OK)
   {
    fprintf(stderr,"Error getting frontierConfig object: %s\n",frontier_getErrorMsg());
    return 2;
   }
  channel=frontier_createChannel2(config,&ec);

  if(ec!=FRONTIER_OK)
   {
    fprintf(stderr,"Error creating frontier channel: %s\n",frontier_getErrorMsg());
    return 2;
   }
  *statelong=channel;
  frontier_setTimeToLive(channel,ttl);
  ziplevel=frontier_getRetrieveZipLevel(channel);

  if(ziplevel==0)
    zipstr[0]='\0';
  else
   {
    zipstr[0]='z';
    zipstr[1]='i';
    zipstr[2]='p';
    zipstr[3]='0'+ziplevel;
    zipstr[4]='\0';
   }


  char *uribuf;
  FrontierRSBlob *frsb;
  int fd;
  int bytes;
  int n;
  char *p;
  char *localname;
  char *encodedquery;//changed argv to query

  encodedquery=doubleurlencode(query);
  uribuf=malloc(strlen(encodedquery)+128);
  sprintf(uribuf,"Frontier/type=frontier_file:1:DEFAULT&encoding=BLOB%s&p1=%s",zipstr,encodedquery);
  free(encodedquery);
  ec=frontier_getRawData(channel,uribuf);
  free(uribuf);
  if(ec!=FRONTIER_OK)
   {
    fprintf(stderr,"Error getting data for %s: %s\n",query[i],frontier_getErrorMsg());
   }
  frsb=frontierRSBlob_open(channel,0,1,&ec);
  if(ec!=FRONTIER_OK)
   {
    fprintf(stderr,"Error opening result blob for %s: %s\n",query[i],frontier_getErrorMsg());
   }
  bytes=0;
  size_t arraysize = 16;                                    //Initialize ptr array size
  size_t blocknumber = 0;                                   //Data blocks allocated
  size_t totalsize = 0;                                     //Size of combined data blocks
  size_t *ptrsizearray = malloc(arraysize*sizeof(size_t));  //Array for the data block sizes
  char **ptrarray = malloc(arraysize*sizeof(char *));       //Array for data block pointers
  if (ptrarray == NULL || ptrsizearray == NULL)
     {
      fprintf(stderr, "Memory Allocation Failed.\n");
     }
  while(1)
   {
    char resulttype=frontierRSBlob_getByte(frsb,&ec);
    if(ec!=FRONTIER_OK)
     {
      fprintf(stderr,"Error getting result type for %s: %s\n",query[i],frontier_getErrorMsg());
      break;
     }
    if(resulttype==RESULT_TYPE_EOR)
      break;
    if(resulttype!=RESULT_TYPE_ARRAY)
     {
      fprintf(stderr,"Unexpected result type for %s: %d\n",query[i],resulttype);
      ec=!FRONTIER_OK;
      break;
     }
    n=frontierRSBlob_getInt(frsb,&ec);
    if(ec!=FRONTIER_OK)
     {
      fprintf(stderr,"Error getting result size for %s: %s\n",query[i],frontier_getErrorMsg());
      break;
     }
    p=frontierRSBlob_getByteArray(frsb,n,&ec);
    if(ec!=FRONTIER_OK)
     {
      fprintf(stderr,"Error getting result data for %s: %s\n",query[i],frontier_getErrorMsg());
      break;
     }
    if (blocknumber == arraysize)                           //Increase ptr array size
     {
      arraysize += 16;
      ptrarray = realloc(ptrarray, arraysize*sizeof(void *));
      ptrsizearray = realloc(ptrsizearray, arraysize*sizeof(size_t));
     }
    if (ptrarray == NULL || ptrsizearray == NULL)
     {
      fprintf(stderr, "Memory Reallocation Failed.\n");
     }
    ptrsizearray[blocknumber] = n;                          //Insert size into array
    char *tmpbuff=malloc(n);
    memcpy(tmpbuff,p,n);
    ptrarray[blocknumber] = tmpbuff;                        //Insert data block ptr into array
    totalsize+=n;                                           //Add size of current block to total
    blocknumber++;
   bytes+=n;
   }
  char *combineddata = malloc(totalsize);                   //Allocate memory for the combined data
  if (combineddata == NULL)
   {
    fprintf(stderr, "Memory Allocation failed\n");
    return 1;
   }
  size_t offset = 0;
  for (size_t i = 0; i < blocknumber; i++)                  //Combine data blocks
   {
    size_t blocksize = ptrsizearray[i];
    char *tmpptr = ptrarray[i];
    memcpy(combineddata+offset,tmpptr,blocksize);
    offset += blocksize;
    free(tmpptr);
   }
  *buff=combineddata;
  free(ptrarray);
  free(ptrsizearray);

  struct statestruct *sstr=malloc(sizeof(struct statestruct));
  sstr->frsb=frsb;
  sstr->buff=*buff;
  *state=(void *)sstr;
  return bytes;
  }
 
void frontier_close(void *state,unsigned long statelong)    //Clean up
 {
  int ec;
  struct statestruct *sstr=(struct statestruct *)state;
  free(sstr->buff);
  frontierRSBlob_close(sstr->frsb,&ec);
  if(ec!=FRONTIER_OK)
    fprintf(stderr, "Error Closing frontier\n");
  free(sstr);
  frontier_closeChannel(statelong);
 }
