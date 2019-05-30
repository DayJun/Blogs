#include <stdlib.h>
#include <stdio.h>
int time(int a)
{
    return atoi(getenv("CURR_TIME"));
}
