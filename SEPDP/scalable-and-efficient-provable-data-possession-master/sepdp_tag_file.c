#include "sepdp.h"
#include <time.h>

int main(int argc, char **argv){  
	SEPDP_challenge *challenge = NULL;
	SEPDP_proof *proof = NULL;
	int i = 0;
	int ret = 0;
	// Time Measurement
	clock_t start,end;
	double cpu_time_used;

	start = clock();
	fprintf(stdout, "Tagging %s...", argv[1]); fflush(stdout);
  	if(!sepdp_setup_file(argv[1], strlen(argv[1]), NULL, 0, SEPDP_NUM_CHALLENGES)){
		printf("Error\n");
	}else{
		end = clock();
		cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
		printf("Done in %f seconds\n", cpu_time_used);
	}	
  return 0;
}
