/*
 * Copyright (C) 2024 Konnek Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* The MIT License (MIT)
 *
 * Copyright (c) <year> <copyright holders>
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the “Software”), to deal in 
 * the Software without restriction, including without limitation the rights to 
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies 
 * of the Software, and to permit persons to whom the Software is furnished to do 
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all 
 * copies or substantial portions of the Software.
 * 
 * The Software is provided “as is”, without warranty of any kind, express or 
 * implied, including but not limited to the warranties of merchantability, 
 * fitness for a particular purpose and noninfringement. In no event shall the 
 * authors or copyright holders be liable for any claim, damages or other 
 * liability, whether in an action of contract, tort or otherwise, arising from, 
 * out of or in connection with the software or the use or other dealings in the 
 * Software. 
 */
 
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/ashmem.h>
#include <linux/memfd.h>
#include <linux/pidfd.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <semaphore.h>
#include <unistd.h>

#include<android/sharedmem.h>
#include <ashm.h>

#define MAX_SHM_FILES 118
#define SHM_STORE_FILE_ENV "ENVAR_SHM_STORE_FD"
#define SHM_STORE_NAME "ashmem_store"

#define FOUND_REGISTRY_PID_FD 1 << 0
#define FOUND_REGISTRY_FD     1 << 1

typedef struct {
	int empty;
	int index;
	int count;
	pid_t pid;
	int memfd;
	char name[ASHMEM_NAME_MAX_LENGTH+1];
} memfd_t;

typedef  memfd_t* memfdptr_t;

static sem_t* sem_memfd = sem_open("/memfd_store_mutex", O_CREAT|O_RDWR, 
				S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH, 1);

static memfd_t* memfd_store = nullptr;	
	
__attribute__((visibility("hidden")))  static int pidfd_open(pid_t pid, unsigned int flags)
{
	return syscall(SYS_pidfd_open, pid, flags);
}

__attribute__((visibility("hidden")))  static int pidfd_getfd(int pidfd, int targetfd, unsigned int flags)
{
	return syscall(SYS_pidfd_getfd, pidfd, targetfd, flags);
}


__attribute__((visibility("hidden")))  static int shm_store_initialize(int memfd){
	memfd_store = (memfd_t*) syscall(SYS_mmap, NULL, ASharedMemory_getSize(memfd), 
					PROT_READ|PROT_WRITE, MAP_SHARED, memfd, 0);
	
	if (memfd_store == MAP_FAILED) {
		close(memfd);
		memfd_store=nullptr;
		#if defined(DEBUG)
			perror("Error mmapping the file");
		#endif
		return -1;
	}

	for(int i = 0; i< MAX_SHM_FILES;i++)
	{
		memfd_store[i].empty = 1;
		memfd_store[i].index = i;
		memfd_store[i].count = 0;
		memfd_store[i].pid = 0; 
		memfd_store[i].memfd = 0;
	}
	return 0;
}
	   
__attribute__((visibility("hidden")))  static int shm_store_create(){
	int memfd = -1;
	if(sem_wait(sem_memfd)==0){
		int memfd = ASharedMemory_create(SHM_STORE_NAME, sizeof(memfd_t)*MAX_SHM_FILES);
		if(memfd >=0){
			pid_t pid = getpid();
			int sz = snprintf(NULL, 0, "/proc/%i/fd/%i", pid, memfd);
			char* proc_pid_fd_name =(char*) malloc(sizeof(char)*(sz+1));
			snprintf(proc_pid_fd_name, sz+1, "/proc/%i/fd/%i",  pid, memfd);
			if(setenv(SHM_STORE_FILE_ENV, proc_pid_fd_name, 1) == -1){
				#if defined(DEBUG)
					perror("shm_store_create.setenv");
				#endif
			}
			free(proc_pid_fd_name);
		}
		if(sem_post(sem_memfd)==-1){
			#if defined(DEBUG)
				perror("shm_store_create.sem_post");
			#endif
		}
	}
	return memfd;
}

__attribute__((visibility("hidden")))  static int shm_store_parse(){
	pid_t pid;
	int regfd = 0;
	int flags = 0;
	if(sem_wait(sem_memfd) == 0){
		#if defined(DEBUG)
			perror("shm_store_create.sem_wait");
		#endif


		char* rest = getenv(SHM_STORE_FILE_ENV);
		char* saveptr;
		char* token = strtok_r(rest, "/", &saveptr);
		for (int i = 0; token!= NULL; i++ )
		{
			if( i == 2)
			{
				pid = atoi(token);
				if(pid > 0) // 0 would be system process or error
				{
					flags |= FOUND_REGISTRY_PID_FD;
				}
			}else if(i == 4){
				regfd = atoi(token);
				if(regfd > 0) // 0 would be stdin or error
				{
					flags |= FOUND_REGISTRY_FD;
				}
			}
			token = strtok_r(NULL, "/", &saveptr); 
		}
		if(sem_post(sem_memfd)==-1){
			#if defined(DEBUG)
				perror("shm_store_create.sem_post");
			#endif
		}
	}
	if((flags & (FOUND_REGISTRY_PID_FD|FOUND_REGISTRY_FD)) == (FOUND_REGISTRY_PID_FD|FOUND_REGISTRY_FD)){
		int pidfd = pidfd_open(pid, PIDFD_NONBLOCK);
		if(pidfd == -1)
		{
			#if defined(DEBUG)
				perror("shm_store_create.memfd");
			#endif
			return shm_store_create();
		}
		
		int memfd = pidfd_getfd(pidfd,regfd,0);
		if(memfd == -1)
		{
			#if defined(DEBUG)
				perror("shm_store_create.pidfd_getfd");
			#endif
			return shm_store_create();
		}
		return memfd;
	}
	return shm_store_create();
}

int shm_init(){
	char * _shm_store_file = getenv(SHM_STORE_FILE_ENV);
	int memfd = _shm_store_file != NULL ? shm_store_create() : shm_store_parse();
	if(memfd <= 0){
		#if defined(DEBUG)
			perror("shm_init.memfd");
		#endif
		unsetenv(SHM_STORE_FILE_ENV);
		return -1;
	}else {
		if(shm_store_initialize(memfd) == -1){
			unsetenv(SHM_STORE_FILE_ENV);
			return -1;
		}
	}
	return memfd;
}


__attribute__((visibility("hidden"))) static bool has_memfd_named(const char* name, memfd_t* entry = nullptr)
{
	bool ret = false;
	if(memfd_store == nullptr){
		shm_init();
	}
		
	if(name!=NULL && memfd_store != nullptr)
	{
		for(int i=0; i<MAX_SHM_FILES;i++)
		{
			if(strcmp(memfd_store[i].name, name)==0)
			{
				ret = true;
				if(entry != nullptr){
					entry->empty = memfd_store[i].empty;
					entry->index = i;
					entry->count =  memfd_store[i].count;
					entry->pid = memfd_store[i].pid;
					entry->memfd = memfd_store[i].memfd;
					stpcpy(entry->name, name);
				}
				break;
			}
		}
	}
	return ret;
}


void* __wrap_mmap(void *addr, size_t length, int prot, int flags,
                  int fd, off_t offset)
{
	int seals = fcntl(fd, F_GET_SEALS);
	if( seals == -1){
		errno = EINVAL;
		return MAP_FAILED;
	}
	
	if (seals & F_SEAL_FUTURE_WRITE) {
		errno = EINVAL;  
		return MAP_FAILED;
	}
	
	struct stat sb;
	if (fstat(fd, &sb) == -1) {
		return MAP_FAILED;
	}
	
	if((seals & (F_SEAL_GROW | F_SEAL_SHRINK)) == 0) {
		if(sb.st_size < length){
			if (ftruncate(fd, length) == -1) {
				return MAP_FAILED;
			}
		}

		// forbid size changes to match ashmem behaviour
		if (fcntl(fd, F_ADD_SEALS, F_SEAL_GROW | F_SEAL_SHRINK) == -1) {
			return MAP_FAILED;
		}
	} else if(sb.st_size < length){
		return MAP_FAILED;
	}
	
    return (void*) syscall(SYS_mmap, addr, length, prot, flags, fd, offset); // if offset !=0 on first call, fail
}

// void* mmap(void *addr, size_t length, int prot, int flags,
//                   int fd, off_t offset) __attribute__((alias("__wrap_mmap")));

__attribute__((visibility("hidden"))) static int shm_memfd_create(const char *name, int oflag){
	int fd = memfd_create(name, MFD_CLOEXEC | MFD_ALLOW_SEALING);
	if (fd == -1) {
		#if defined(DEBUG)
			perror("shm_open.memfd_create");
		#endif
		return -1;
	}

	if (oflag & O_CREAT) {
		if (ftruncate(fd, 0) == -1) {
			#if defined(DEBUG)
				perror("shm_open.ftruncate");
			#endif				
			close(fd);
			return -1;
		}
	}
	return fd;
}

__attribute__((visibility("hidden"))) static int shm_memfd_store_insert(const char *name, pid_t pid, int memfd){
	if(memfd_store != nullptr)
	{
		for(int i=0;i<MAX_SHM_FILES;i++)
		{
			if(memfd_store[i].empty==1){
				memfd_store[i].pid=pid;
				memfd_store[i].memfd = memfd;
				strcpy(memfd_store[i].name,name);
				memfd_store[i].empty = 0;
				return i;
			}
		}
	}
	return -1;
}

// Create or open a shared memory object
int shm_open(const char *name, int oflag, mode_t mode) {
	// This code needs to build on old API levels, so we can't use the libc
    // wrapper.
	
	memfd_t entry;
	if(!has_memfd_named(name, &entry))
	{
		if(sem_wait(sem_memfd)==0){
			int memfd = shm_memfd_create(name,oflag);
			if(memfd>=0){
				pid_t pid = getpid();
				entry.index = shm_memfd_store_insert(name, pid, memfd);
			}
			sem_post(sem_memfd);
			entry.memfd = memfd;
		}
	} 
	if(entry.memfd >=0 && entry.index != -1)
	{
		memfd_store[entry.index].count++;
	}
	return entry.memfd;
}

// Unlink (delete) a shared memory object
int shm_unlink(const char *name) {
	memfd_t entry;
	if(has_memfd_named(name, &entry))
	{
		int pidfd = pidfd_open(entry.pid, PIDFD_NONBLOCK);
		if(pidfd == -1)
		{
			#if defined(DEBUG)
				perror("shm_unlink.pidfd");
			#endif
			return -1;
		}
		
		int memfd = pidfd_getfd(pidfd, entry.memfd, 0);
		if(memfd == -1)
		{
			#if defined(DEBUG)
				perror("shm_unlink.memfd");
			#endif
			return -1;
		}
		// prevent future mmap
		int seals = fcntl(memfd, F_GET_SEALS);
		if( seals != -1 && (seals & F_SEAL_SEAL) == 0){
			// forbid future mapping
			if (fcntl(memfd, F_ADD_SEALS, F_SEAL_FUTURE_WRITE | F_SEAL_SEAL) == -1) {
				#if defined(DEBUG)
					perror("shm_unlink.memfd");
				#endif
			}
		}
		close(memfd);
		if(memfd_store[entry.index].empty!=1 && --(memfd_store[entry.index].count) <=0){ // clamp count to 0
			memfd_store[entry.index].empty=1;
			memfd_store[entry.index].count=0;
		}
	}
    return 0;
}
