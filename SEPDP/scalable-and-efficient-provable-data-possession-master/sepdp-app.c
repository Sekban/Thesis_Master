/* 
* sepdp-app.c
*
* Copyright (c) 2010, Zachary N J Peterson <znpeters@nps.edu>
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*     * Redistributions of source code must retain the above copyright
*       notice, this list of conditions and the following disclaimer.
*     * Redistributions in binary form must reproduce the above copyright
*       notice, this list of conditions and the following disclaimer in the
*       documentation and/or other materials provided with the distribution.
*     * Neither the name of the Naval Postgraduate School nor the
*       names of its contributors may be used to endorse or promote products
*       derived from this software without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY ZACHARY N J PETERSON ``AS IS'' AND ANY
* EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL ZACHARY N J PETERSON BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

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
#ifdef USE_S3
	char tokenfilepath[MAXPATHLEN];
#endif	
	start = clock();
	fprintf(stdout, "Tagging %s...", argv[1]); fflush(stdout);
  	if(!sepdp_setup_file(argv[1], strlen(argv[1]), NULL, 0, SEPDP_NUM_CHALLENGES)){
		printf("Error\n");
	}else{
		end = clock();
		cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
		printf("Done in %f seconds\n", cpu_time_used);
	}	

#ifdef USE_S3
	fprintf(stdout, "Writing file %s to S3...", argv[1]); fflush(stdout);
	if(!sepdp_s3_put_file(argv[1], strlen(argv[1]))) printf("Couldn't write %s to S3.\n", argv[1]);
	else printf("Done.\n");
	
	memset(tokenfilepath, 0, MAXPATHLEN);
	snprintf(tokenfilepath, MAXPATHLEN, "%s.tok", argv[1]);
	fprintf(stdout, "Writing token file %s to S3...", tokenfilepath); fflush(stdout);
	if(!sepdp_s3_put_file(tokenfilepath, strlen(tokenfilepath))) printf("Couldn't write %s to S3.\n", argv[1]);
	else printf("Done.\n");				
#endif	
	fprintf(stdout, "Challenging file %s...\n", argv[1]); fflush(stdout);				
	
	for(i = 0; i < 5; i++){
		start = clock();
		fprintf(stdout, "\tCreating challenge %d for %s...", i, argv[1]); fflush(stdout);
		challenge = sepdp_challenge_file(argv[1], strlen(argv[1]),  i);
		if(!challenge){ printf("No challenge!\n"); return -1;}else{
			end = clock();
			cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
			printf("Done in %f seconds.\n", cpu_time_used);
		}
		
		printf("\tComputing proof...");fflush(stdout);
		start = clock();
#ifdef USE_S3	
		proof = sepdp_s3_prove_file(argv[1], strlen(argv[1]),  NULL, 0, challenge);
#else
		proof = sepdp_prove_file(argv[1], strlen(argv[1]),  NULL, 0, challenge);
#endif
		if(!proof){ printf("No proof!\n"); return -1;}else{
			end = clock();
			cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
			printf("Done in %f seconds.\n", cpu_time_used);
		}
		printf("\tVerifying proof...");fflush(stdout);
		ret = sepdp_verify_file(proof);
		end = clock();
		cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
		if(ret == 0)printf("Verified in %f seconds!\n", cpu_time_used);
		else printf("Found Cheating in %f seconds!\n", cpu_time_used);
		
		if(challenge) destroy_sepdp_challenge(challenge);
		if(proof) destroy_sepdp_proof(proof);
	}



  return 0;
  
}
