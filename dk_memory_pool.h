/**
 * @author David Kviloria <david@skystargames.com>
 * STB Style library.
 */
#ifndef DK_MEMORY_POOL_H
#define DK_MEMORY_POOL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

#define DK_POOL_DEFAULT_CHUNK_SIZE 64
#define DK_POOL_DEFAULT_CHUNK_COUNT 1024
#define DK_POOL_DEBUG 1
#define DK_POOL_STATS 1
#define DK_POOL_GUARD_BYTES 0
#define DK_POOL_THREAD_SAFE 0

typedef struct DK_PoolHeader
{
	uint32_t              magic;
	struct DK_PoolHeader *next;
	size_t                size;
	uint32_t              flags;
#if DK_POOL_DEBUG
	const char *file;
	int         line;
	uint64_t    timestamp;
#endif
} DK_PoolHeader;

#define DK_POOL_FLAG_FREE 0x00000001
#define DK_POOL_FLAG_GUARD 0x00000002
#define DK_POOL_FLAG_INVALID 0x00000004
#define DK_POOL_FLAG_POISON 0x00000008

typedef struct DK_MemoryPool
{
	void          *memory;
	size_t         chunk_size;
	size_t         total_chunks;
	size_t         free_chunks;
	DK_PoolHeader *free_list;

	// Virtual memory info
	size_t page_size;
	size_t total_size;
	bool   uses_virtual_memory;

	// Guard bytes and debug
	size_t header_size;
	size_t usable_chunk_size;

	// Statistics
#if DK_POOL_STATS
	size_t total_allocations;
	size_t current_allocations;
	size_t peak_allocations;
	size_t allocation_failures;
#endif

#if DK_POOL_THREAD_SAFE
	void *mutex;
#endif
} DK_MemoryPool;

#if DK_POOL_DEBUG
DK_MemoryPool *DK_MemoryPoolCreate( size_t chunk_size, size_t chunk_count );
void          *DK_MemoryPoolAllocDebug( DK_MemoryPool *pool, const char *file, int line );
void           DK_MemoryPoolFreeDebug( DK_MemoryPool *pool, void *ptr, const char *file, int line );
#define DK_MemoryPoolAlloc( pool ) DK_MemoryPoolAllocDebug( pool, __FILE__, __LINE__ )
#define DK_MemoryPoolFree( pool, ptr ) DK_MemoryPoolFreeDebug( pool, ptr, __FILE__, __LINE__ )
#else
DK_MemoryPool *DK_MemoryPoolCreate( size_t chunk_size, size_t chunk_count );
void          *DK_MemoryPoolAlloc( DK_MemoryPool *pool );
void           DK_MemoryPoolFree( DK_MemoryPool *pool, void *ptr );
#endif

void DK_MemoryPoolDestroy( DK_MemoryPool *pool );
void DK_MemoryPoolReset( DK_MemoryPool *pool );

typedef struct DK_PoolStats
{
	size_t total_size;
	size_t chunk_size;
	size_t usable_chunk_size;
	size_t total_chunks;
	size_t free_chunks;
	float  utilization; // ratio (0.0 - 1.0)
	size_t total_allocations;
	size_t current_allocations;
	size_t peak_allocations;
	size_t allocation_failures;
} DK_PoolStats;

void DK_MemoryPoolGetStats( DK_MemoryPool *pool, DK_PoolStats *stats );
void DK_MemoryPoolPrintStats( DK_MemoryPool *pool );
bool DK_MemoryPoolValidate( DK_MemoryPool *pool );

#ifdef DK_MEMORY_POOL_IMPLEMENTATION

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define DK_POOL_MAGIC 0x504F4F4C // "POOL" in ASCII

#if DK_POOL_GUARD_BYTES > 0
static const uint8_t DK_POOL_GUARD_PATTERN[] = { 0xFD, 0xFD, 0xFD, 0xFD, 0xFD, 0xFD, 0xFD, 0xFD };
#endif

#ifdef _WIN32
static size_t DK_PoolGetSystemPageSize()
{
	SYSTEM_INFO si;
	GetSystemInfo( &si );
	return si.dwPageSize;
}

static void *DK_ReserveAndCommitMemory( size_t size )
{
	return VirtualAlloc( NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );
}

static void DK_FreeVirtualMemory( void *ptr )
{
	VirtualFree( ptr, 0, MEM_RELEASE );
}
#else
static size_t DK_PoolGetSystemPageSize()
{
	return (size_t)sysconf( _SC_PAGESIZE );
}

static void *DK_ReserveAndCommitMemory( size_t size )
{
	void *ptr = mmap( NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0 );
	return ( ptr == MAP_FAILED ) ? NULL : ptr;
}

static void DK_FreeVirtualMemory( void *ptr, size_t size )
{
	munmap( ptr, size );
}
#endif

static inline size_t DK_PoolAlignUp( size_t n, size_t alignment )
{
	return ( n + alignment - 1 ) & ~( alignment - 1 );
}

static size_t DK_CalculateChunkSize( size_t requested_chunk_size )
{
	size_t header_size = DK_PoolAlignUp( sizeof( DK_PoolHeader ), 16 );

#if DK_POOL_GUARD_BYTES > 0
	size_t guard_size = DK_POOL_GUARD_BYTES;
	size_t total_size = header_size + requested_chunk_size + guard_size;
#else
	size_t total_size = header_size + requested_chunk_size;
#endif

	return DK_PoolAlignUp( total_size, 16 );
}

DK_MemoryPool *DK_MemoryPoolCreate( size_t chunk_size, size_t chunk_count )
{
	if ( chunk_size == 0 )
	{
		chunk_size = DK_POOL_DEFAULT_CHUNK_SIZE;
	}

	if ( chunk_count == 0 )
	{
		chunk_count = DK_POOL_DEFAULT_CHUNK_COUNT;
	}

	DK_MemoryPool *pool = (DK_MemoryPool *)malloc( sizeof( DK_MemoryPool ) );
	if ( !pool )
	{
		return NULL;
	}

	memset( pool, 0, sizeof( DK_MemoryPool ) );

	size_t header_size      = DK_PoolAlignUp( sizeof( DK_PoolHeader ), 16 );
	size_t total_chunk_size = DK_CalculateChunkSize( chunk_size );
	size_t total_size       = total_chunk_size * chunk_count;

	pool->chunk_size        = chunk_size;
	pool->total_chunks      = chunk_count;
	pool->free_chunks       = chunk_count;
	pool->header_size       = header_size;
	pool->usable_chunk_size = chunk_size;
	pool->total_size        = total_size;

	pool->page_size = DK_PoolGetSystemPageSize();

	if ( total_size >= pool->page_size )
	{
		pool->memory              = DK_ReserveAndCommitMemory( total_size );
		pool->uses_virtual_memory = true;
	}
	else
	{
		pool->memory              = malloc( total_size );
		pool->uses_virtual_memory = false;
	}

	if ( !pool->memory )
	{
		free( pool );
		return NULL;
	}

	pool->free_list     = NULL;
	char *current_chunk = (char *)pool->memory;

	for ( size_t i = 0; i < chunk_count; i++ )
	{
		DK_PoolHeader *header = (DK_PoolHeader *)current_chunk;

		header->magic = DK_POOL_MAGIC;
		header->size  = chunk_size;
		header->flags = DK_POOL_FLAG_FREE;

		header->next    = pool->free_list;
		pool->free_list = header;

#if DK_POOL_GUARD_BYTES > 0
		char *guard_position = current_chunk + header_size + chunk_size;
		memcpy( guard_position, DK_POOL_GUARD_PATTERN, DK_POOL_GUARD_BYTES );
		header->flags |= DK_POOL_FLAG_GUARD;
#endif

		current_chunk += total_chunk_size;
	}

#if DK_POOL_THREAD_SAFE
	// TODO (David) implement thread safe implementation
	pool->mutex = NULL;
#endif

	return pool;
}

void DK_MemoryPoolDestroy( DK_MemoryPool *pool )
{
	if ( !pool )
	{
		return;
	}

#if DK_POOL_STATS
	if ( pool->current_allocations > 0 )
	{
		fprintf( stderr,
		         "Warning: Destroying memory pool with %zu active allocations\n",
		         pool->current_allocations );
		DK_MemoryPoolPrintStats( pool );
	}
#endif

#if DK_POOL_THREAD_SAFE
	// Destroy mutex
	// TODO (David) implement thread safe implementation
#endif

	if ( pool->uses_virtual_memory )
	{
#ifdef _WIN32
		DK_FreeVirtualMemory( pool->memory );
#else
		DK_FreeVirtualMemory( pool->memory, pool->total_size );
#endif
	}
	else
	{
		free( pool->memory );
	}

	free( pool );
}

#if DK_POOL_DEBUG
void *DK_MemoryPoolAllocDebug( DK_MemoryPool *pool, const char *file, int line )
{
#else
void *DK_MemoryPoolAlloc( DK_MemoryPool *pool )
{
#endif
	if ( !pool )
	{
		return NULL;
	}

#if DK_POOL_THREAD_SAFE
	// Lock mutex
	// TODO (David) implement thread safe implementation
#endif

	if ( !pool->free_list )
	{
#if DK_POOL_STATS
		pool->allocation_failures++;
#endif

#if DK_POOL_THREAD_SAFE
		// Unlock mutex
		// TODO (David) implement thread safe implementation
#endif
		return NULL;
	}

	DK_PoolHeader *header = pool->free_list;
	pool->free_list       = header->next;
	pool->free_chunks--;

	header->flags &= ~DK_POOL_FLAG_FREE;
	header->next = NULL;

#if DK_POOL_DEBUG
	header->file      = file;
	header->line      = line;
	header->timestamp = (uint64_t)time( NULL );
#endif

#if DK_POOL_STATS
	pool->total_allocations++;
	pool->current_allocations++;
	if ( pool->current_allocations > pool->peak_allocations )
	{
		pool->peak_allocations = pool->current_allocations;
	}
#endif

#if DK_POOL_THREAD_SAFE
	// Unlock mutex
	// TODO (David) implement thread safe implementation
#endif

	return (void *)( (char *)header + pool->header_size );
}

#if DK_POOL_DEBUG
void DK_MemoryPoolFreeDebug( DK_MemoryPool *pool, void *ptr, const char *file, int line )
{
#else
void DK_MemoryPoolFree( DK_MemoryPool *pool, void *ptr )
{
#endif
	if ( !pool || !ptr )
	{
		return;
	}

	DK_PoolHeader *header = (DK_PoolHeader *)( (char *)ptr - pool->header_size );
	if ( header->magic != DK_POOL_MAGIC )
	{
		fprintf( stderr, "Error: Invalid memory pool chunk header (magic number mismatch)\n" );
		return;
	}

	if ( header->flags & DK_POOL_FLAG_FREE )
	{
		fprintf( stderr, "Error: Double free detected in memory pool\n" );
#if DK_POOL_DEBUG
		fprintf( stderr, "    Original allocation: %s:%d\n", header->file, header->line );
		fprintf( stderr, "    Double free attempted: %s:%d\n", file, line );
#endif
		return;
	}

#if DK_POOL_GUARD_BYTES > 0
	if ( header->flags & DK_POOL_FLAG_GUARD )
	{
		char *guard_position = (char *)header + pool->header_size + header->size;
		if ( memcmp( guard_position, DK_POOL_GUARD_PATTERN, DK_POOL_GUARD_BYTES ) != 0 )
		{
			fprintf( stderr, "Error: Memory corruption detected (guard bytes modified)\n" );
#if DK_POOL_DEBUG
			fprintf( stderr, "    Allocation: %s:%d\n", header->file, header->line );
#endif
			return;
		}
	}
#endif

#if DK_POOL_THREAD_SAFE
	// Lock mutex
	// TODO (David) implement thread safe implementation
#endif

	header->flags |= DK_POOL_FLAG_FREE;

	header->next    = pool->free_list;
	pool->free_list = header;
	pool->free_chunks++;

#if DK_POOL_STATS
	pool->current_allocations--;
#endif

#if DK_POOL_THREAD_SAFE
	// Unlock mutex
	// TODO (David) implement thread safe implementation
#endif

#if DK_POOL_DEBUG
	memset( ptr, 0xDD, header->size );
	header->flags |= DK_POOL_FLAG_POISON;
#endif
}

void DK_MemoryPoolReset( DK_MemoryPool *pool )
{
	if ( !pool )
	{
		return;
	}

#if DK_POOL_THREAD_SAFE
	// Lock mutex
	// TODO (David) implement thread safe implementation
#endif

	pool->free_list = NULL;

	size_t total_chunk_size = DK_CalculateChunkSize( pool->chunk_size );
	char  *current_chunk    = (char *)pool->memory;

	for ( size_t i = 0; i < pool->total_chunks; i++ )
	{
		DK_PoolHeader *header = (DK_PoolHeader *)current_chunk;

		header->flags   = DK_POOL_FLAG_FREE;
		header->next    = pool->free_list;
		pool->free_list = header;

#if DK_POOL_GUARD_BYTES > 0
		char *guard_position = current_chunk + pool->header_size + pool->chunk_size;
		memcpy( guard_position, DK_POOL_GUARD_PATTERN, DK_POOL_GUARD_BYTES );
		header->flags |= DK_POOL_FLAG_GUARD;
#endif

#if DK_POOL_DEBUG
		memset( current_chunk + pool->header_size, 0xDD, pool->chunk_size );
		header->flags |= DK_POOL_FLAG_POISON;
#endif

		current_chunk += total_chunk_size;
	}

	pool->free_chunks = pool->total_chunks;

#if DK_POOL_STATS
	pool->current_allocations = 0;
#endif

#if DK_POOL_THREAD_SAFE
	// Unlock mutex
	// TODO (David) implement thread safe implementation
#endif
}

void DK_MemoryPoolGetStats( DK_MemoryPool *pool, DK_PoolStats *stats )
{
	if ( !pool || !stats )
	{
		return;
	}

	memset( stats, 0, sizeof( DK_PoolStats ) );

	stats->total_size        = pool->total_size;
	stats->chunk_size        = pool->chunk_size;
	stats->usable_chunk_size = pool->usable_chunk_size;
	stats->total_chunks      = pool->total_chunks;
	stats->free_chunks       = pool->free_chunks;

	if ( pool->total_chunks > 0 )
	{
		stats->utilization = (float)( pool->total_chunks - pool->free_chunks ) / (float)pool->total_chunks;
	}

#if DK_POOL_STATS
	stats->total_allocations   = pool->total_allocations;
	stats->current_allocations = pool->current_allocations;
	stats->peak_allocations    = pool->peak_allocations;
	stats->allocation_failures = pool->allocation_failures;
#endif
}

void DK_MemoryPoolPrintStats( DK_MemoryPool *pool )
{
	if ( !pool )
	{
		return;
	}

	DK_PoolStats stats;
	DK_MemoryPoolGetStats( pool, &stats );

	printf( "===== Memory Pool Statistics =====\n" );
	printf( "Total memory: %zu bytes (%.2f KB)\n", stats.total_size, stats.total_size / 1024.0f );
	printf( "Chunk size: %zu bytes (usable: %zu bytes)\n", stats.chunk_size, stats.usable_chunk_size );
	printf( "Total chunks: %zu\n", stats.total_chunks );
	printf( "Free chunks: %zu (%.1f%%)\n",
	        stats.free_chunks,
	        (float)stats.free_chunks / stats.total_chunks * 100.0f );
	printf( "Utilization: %.1f%%\n", stats.utilization * 100.0f );

#if DK_POOL_STATS
	printf( "Total allocations: %zu\n", stats.total_allocations );
	printf( "Current allocations: %zu\n", stats.current_allocations );
	printf( "Peak allocations: %zu\n", stats.peak_allocations );
	printf( "Allocation failures: %zu\n", stats.allocation_failures );
#endif

	printf( "=================================\n" );
}

bool DK_MemoryPoolValidate( DK_MemoryPool *pool )
{
	if ( !pool )
	{
		fprintf( stderr, "Error: NULL pool pointer\n" );
		return false;
	}

	printf( "Validating memory pool integrity...\n" );

	bool   valid           = true;
	size_t free_count      = 0;
	size_t allocated_count = 0;

	size_t total_chunk_size = DK_CalculateChunkSize( pool->chunk_size );
	char  *current_chunk    = (char *)pool->memory;

	for ( size_t i = 0; i < pool->total_chunks; i++ )
	{
		DK_PoolHeader *header = (DK_PoolHeader *)current_chunk;
		if ( header->magic != DK_POOL_MAGIC )
		{
			fprintf( stderr, "Error: Invalid magic number in chunk %zu\n", i );
			valid = false;
		}

#if DK_POOL_GUARD_BYTES > 0
		if ( header->flags & DK_POOL_FLAG_GUARD )
		{
			char *guard_position = current_chunk + pool->header_size + pool->chunk_size;
			if ( memcmp( guard_position, DK_POOL_GUARD_PATTERN, DK_POOL_GUARD_BYTES ) != 0 )
			{
				fprintf( stderr, "Error: Guard bytes corrupted in chunk %zu\n", i );
#if DK_POOL_DEBUG
				if ( !( header->flags & DK_POOL_FLAG_FREE ) )
				{
					fprintf( stderr, "    Allocation: %s:%d\n", header->file, header->line );
				}
#endif
				valid = false;
			}
		}
#endif

		if ( header->flags & DK_POOL_FLAG_FREE )
		{
			free_count++;
		}
		else
		{
			allocated_count++;
		}

		current_chunk += total_chunk_size;
	}

	size_t         free_list_count = 0;
	DK_PoolHeader *current         = pool->free_list;

	while ( current )
	{
		if ( current->magic != DK_POOL_MAGIC )
		{
			fprintf( stderr, "Error: Invalid magic number in free list entry\n" );
			valid = false;
			break;
		}

		if ( !( current->flags & DK_POOL_FLAG_FREE ) )
		{
			fprintf( stderr, "Error: Chunk in free list is not marked as free\n" );
			valid = false;
		}

		free_list_count++;
		current = current->next;

		if ( free_list_count > pool->total_chunks )
		{
			fprintf( stderr, "Error: Potential cycle detected in free list\n" );
			valid = false;
			break;
		}
	}

	if ( free_list_count != pool->free_chunks )
	{
		fprintf( stderr,
		         "Error: Free list count (%zu) doesn't match free_chunks (%zu)\n",
		         free_list_count,
		         pool->free_chunks );
		valid = false;
	}

	if ( free_count + allocated_count != pool->total_chunks )
	{
		fprintf( stderr,
		         "Error: Sum of free (%zu) and allocated (%zu) chunks doesn't match "
		         "total (%zu)\n",
		         free_count,
		         allocated_count,
		         pool->total_chunks );
		valid = false;
	}

	printf( "Validation %s. Found %zu free, %zu allocated chunks\n",
	        valid ? "passed" : "failed",
	        free_count,
	        allocated_count );

	return valid;
}

#endif // DK_MEMORY_POOL_IMPLEMENTATION
#endif // DK_MEMORY_POOL_H