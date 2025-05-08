#ifndef FRONTIER_PROTOCOL_H
#define FRONTIER_PROTOCOL_H

void doubleurlencode(const char *frombuf);

int frontierretrieve(void **state,unsigned long *statelong,const char *connectstr,char *query,char **buff);


void frontier_close(void *state,unsigned long statelong);

#endif
