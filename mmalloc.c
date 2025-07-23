#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

typedef char ALIGN[16];

union header {
	struct {
		size_t size;
		unsigned is_free;
		union header *next;
		union header *prev;
	} s;
	ALIGN stub;
};

typedef union header header_t;

header_t *head = NULL, *tail = NULL;
pthread_mutex_t global_malloc_lock;

header_t *get_free_block(size_t size) {
	header_t *curr = head;
	while(curr) {
		if (curr->s.is_free && curr->s.size >= size)
			return curr;
		curr = curr->s.next;
	}
	return NULL;
}

void free(void *block) {
	if (!block) {
		return;
	}

	pthread_mutex_lock(&global_malloc_lock);
	header_t *header = (header_t*)block - 1;

	// Try to coalesce with the previous block.
	if (header->s.prev && header->s.prev->s.is_free) {
		header->s.prev->s.size += sizeof(header_t) + header->s.size;
		header->s.prev->s.next = header->s.next;
		if (header->s.next) {
			header->s.next->s.prev = header->s.prev;
		}
	    // The current block is now the merged block.
	    header = header->s.prev;
		// If the freed block was the tail, the previous block is now the new tail.
		if (header == tail) {
			tail = header;
		}
	}

	// Try to coalesce with the next block.
	if (header->s.next && header->s.next->s.is_free) {
		// The next block is free, so merge it into this one.
		header->s.size += sizeof(header_t) + header->s.next->s.size;
		header->s.next = header->s.next->s.next;
		if (header->s.next) {
			header->s.next->s.prev = header;
		}
		// If the next block was the tail, this merged block is the new tail.
		if (header->s.next == NULL) {
			tail = header;
		}
	}

	header->s.is_free = 1;

	if (header == tail) {
		if (head == tail) {
			head = tail = NULL;
		} else {
			tail = header->s.prev;
			tail->s.next = NULL;
		}
		sbrk(0 - sizeof(header_t) - header->s.size);
	}

	pthread_mutex_unlock(&global_malloc_lock);
}

void* malloc(size_t size) {
	if (!size) {
		return NULL;
	}

	pthread_mutex_lock(&global_malloc_lock);
	header_t *header = get_free_block(size);

    // Split block if possible.
	if (header) {
		// Ensure a minimal payload of 8 bytes.
		if ((header->s.size - size) >= (sizeof(header_t) + 8)) {
			header_t *new_header = (header_t*)((char*)header + sizeof(header_t) + size);
			new_header->s.is_free = 1;
			new_header->s.size = header->s.size - size - sizeof(header_t);

			new_header->s.prev = header;
			new_header->s.next = header->s.next;
			if (new_header->s.next) {
				new_header->s.next->s.prev = new_header;
			}

			header->s.next = new_header;
			header->s.size = size;
			if (header == tail) {
				tail = new_header;
			}
		}
		header->s.is_free = 0;
		pthread_mutex_unlock(&global_malloc_lock);
		return header + 1;
	}

	// No free block found, so request new memory from the OS.
	size_t total_size = sizeof(header_t) + size;
	void *block = sbrk(total_size);
	if (block == (void*) -1) {
		pthread_mutex_unlock(&global_malloc_lock);
		return NULL;
	}

	header = (header_t*)block;
	header->s.size = size;
	header->s.is_free = 0;
	header->s.next = NULL;
	header->s.prev = tail;

	if (!head) {
		head = header;
	}
	if (tail) {
		tail->s.next = header;
	}
	tail = header;
	pthread_mutex_unlock(&global_malloc_lock);

	return header + 1;
}

void *calloc(size_t num, size_t nsize) {
	size_t size;
	void *block;
	if (!num || !nsize)
		return NULL;
	size = num * nsize;
	// Check mul overflow.
	if (nsize != size / num)
		return NULL;
	block = malloc(size);
	if (!block)
		return NULL;
	memset(block, 0, size);
	return block;
}

void *realloc(void *block, size_t size) {
	header_t *header;
	void *ret;
	if (!block || !size)
		return malloc(size);
	header = (header_t*)block - 1;
	if (header->s.size >= size)
		return block;
	ret = malloc(size);
	if (ret) {
		memcpy(ret, block, header->s.size);
		free(block);
	}
	return ret;
}

void print_mem_list() {
	header_t *curr = head;
	printf("head = %p, tail = %p \n", (void*)head, (void*)tail);
	while(curr) {
		printf("addr = %p, size = %zu, is_free=%u, next=%p, prev=%p\n",
			(void*)curr, curr->s.size, curr->s.is_free, (void*)curr->s.next, (void*)curr->s.prev);
		curr = curr->s.next;
	}
}

int main() {
    printf("--- Test: Malloc, then Free ---\n");
    void* p1 = malloc(100);
    print_mem_list();
    free(p1);
    print_mem_list();
    printf("\n--- Test: Block Splitting ---\n");
    void* p2 = malloc(2000);
    printf("Allocated 2000 bytes:\n");
    print_mem_list();
    void* p3 = malloc(50);
    printf("\nAllocated 50 bytes. The first block should now be split:\n");
    print_mem_list();
    free(p2);
    free(p3);

    printf("\n--- Test: Coalescing ---\n");
    void* c1 = malloc(100);
    void* c2 = malloc(200);
    void* c3 = malloc(300);
    printf("Allocated three blocks:\n");
    print_mem_list();
    printf("\nFreeing the middle block (c2). No coalescing yet:\n");
    free(c2);
    print_mem_list();
    printf("\nFreeing the first block (c1). Should merge with c2's free space:\n");
    free(c1);
    print_mem_list();
    printf("\nFreeing the last block (c3). Should merge with the other free space and then release to OS:\n");
    free(c3);
    print_mem_list();

    return 0;
}