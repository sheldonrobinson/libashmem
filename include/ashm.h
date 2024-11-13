#include <sys/types.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define ASHMEM_NAME_MAX_LENGTH 255

int shm_init();
void* __wrap_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int shm_open(const char *name, int oflag, mode_t mode);
int shm_unlink(const char *name);

#ifdef __cplusplus
}

#endif
