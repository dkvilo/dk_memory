/**
 * @author David Kviloria <david@skystargames.com>
 * STB Style library.
 */
#ifndef DK_RING_BUFFER_H
#define DK_RING_BUFFER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

#define DK_RING_DEFAULT_SIZE ( 1024 * 1024 ) // 1MB
#define DK_RING_DEBUG 1
#define DK_RING_STATS 1
#define DK_RING_THREAD_SAFE 0
#define DK_RING_MIN_ALIGNMENT 16
#define DK_RING_DOUBLE_MAPPING 1

typedef struct DK_RingHeader
{
	uint32_t magic;
	size_t   size;
	uint32_t flags;
#if DK_RING_DEBUG
	const char *file;
	int         line;
	uint64_t    timestamp;
#endif
} DK_RingHeader;

#define DK_RING_FLAG_USED 0x00000001
#define DK_RING_FLAG_INVALID 0x00000002
#define DK_RING_FLAG_PADDING 0x00000004

typedef struct DK_RingBuffer
{
	void  *memory;
	size_t size;

	size_t head;
	size_t tail;
	size_t active;

	// Virtual memory info
	size_t page_size;
	bool   uses_virtual_memory;
	bool   is_double_mapped;

	// Header and alignment
	size_t header_size;
	size_t min_alignment;

	// Statistics
#if DK_RING_STATS
	size_t total_allocations;
	size_t failed_allocations;
	size_t bytes_allocated;
	size_t peak_bytes_allocated;
	size_t largest_allocation;
	size_t wraparounds;
#endif

#if DK_RING_THREAD_SAFE
	void *mutex;
#endif
} DK_RingBuffer;

#if DK_RING_DEBUG
DK_RingBuffer *DK_RingBufferCreate( size_t size );
void          *DK_RingBufferAllocDebug( DK_RingBuffer *ring, size_t size, const char *file, int line );
void           DK_RingBufferFreeDebug( DK_RingBuffer *ring, void *ptr, const char *file, int line );
#define DK_RingBufferAlloc( ring, size ) DK_RingBufferAllocDebug( ring, size, __FILE__, __LINE__ )
#define DK_RingBufferFree( ring, ptr ) DK_RingBufferFreeDebug( ring, ptr, __FILE__, __LINE__ )
#else
DK_RingBuffer *DK_RingBufferCreate( size_t size );
void          *DK_RingBufferAlloc( DK_RingBuffer *ring, size_t size );
void           DK_RingBufferFree( DK_RingBuffer *ring, void *ptr );
#endif

void  DK_RingBufferDestroy( DK_RingBuffer *ring );
void  DK_RingBufferReset( DK_RingBuffer *ring );
void *DK_RingBufferAllocAligned( DK_RingBuffer *ring, size_t size, size_t alignment );

typedef struct DK_RingStats
{
	size_t total_size;
	size_t used_size;
	float  utilization; // (0.0 - 1.0)
	size_t active_allocations;
	size_t total_allocations;
	size_t failed_allocations;
	size_t largest_allocation;
	size_t peak_memory_used;
	size_t wraparounds;
} DK_RingStats;

void   DK_RingBufferGetStats( DK_RingBuffer *ring, DK_RingStats *stats );
void   DK_RingBufferPrintStats( DK_RingBuffer *ring );
bool   DK_RingBufferValidate( DK_RingBuffer *ring );
size_t DK_RingBufferGetFreeSpace( DK_RingBuffer *ring );

#ifdef DK_RING_BUFFER_IMPLEMENTATION

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define DK_RING_MAGIC 0x52494E47 // "RING" in ASCII

#ifdef _WIN32
static size_t DK_RingGetSystemPageSize()
{
	SYSTEM_INFO si;
	GetSystemInfo( &si );
	return si.dwPageSize;
}

#if DK_RING_DOUBLE_MAPPING

static void *DK_RingCreateDoubleMapping( size_t size )
{
	char *base_addr = (char *)VirtualAlloc( NULL, size * 2, MEM_RESERVE, PAGE_NOACCESS );
	if ( !base_addr )
	{
		return NULL;
	}

	if ( !VirtualFree( base_addr + size, size, MEM_RELEASE ) )
	{
		VirtualFree( base_addr, 0, MEM_RELEASE );
		return NULL;
	}

	HANDLE file_mapping = CreateFileMapping( INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, size, NULL );
	if ( file_mapping == NULL )
	{
		VirtualFree( base_addr, 0, MEM_RELEASE );
		return NULL;
	}

	if ( MapViewOfFileEx( file_mapping, FILE_MAP_ALL_ACCESS, 0, 0, size, base_addr ) == NULL )
	{
		CloseHandle( file_mapping );
		VirtualFree( base_addr, 0, MEM_RELEASE );
		return NULL;
	}

	if ( MapViewOfFileEx( file_mapping, FILE_MAP_ALL_ACCESS, 0, 0, size, base_addr + size ) == NULL )
	{
		UnmapViewOfFile( base_addr );
		CloseHandle( file_mapping );
		VirtualFree( base_addr, 0, MEM_RELEASE );
		return NULL;
	}

	CloseHandle( file_mapping );
	return base_addr;
}

static void DK_RingDestroyDoubleMapping( void *addr, size_t size )
{
	UnmapViewOfFile( addr );
	UnmapViewOfFile( (char *)addr + size );
	VirtualFree( addr, 0, MEM_RELEASE );
}
#else
static void *DK_RingAllocateMemory( size_t size )
{
	return VirtualAlloc( NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );
}

static void DK_RingFreeMemory( void *addr )
{
	VirtualFree( addr, 0, MEM_RELEASE );
}
#endif

#else // Linux/Unix implementation
static size_t DK_RingGetSystemPageSize()
{
	return (size_t)sysconf( _SC_PAGESIZE );
}

#if DK_RING_DOUBLE_MAPPING
static void *DK_RingCreateDoubleMapping( size_t size )
{
	char tempname[] = "/tmp/ringbuffer-XXXXXX";
	int  fd         = mkstemp( tempname );
	if ( fd == -1 )
	{
		return NULL;
	}

	unlink( tempname );

	if ( ftruncate( fd, size ) == -1 )
	{
		close( fd );
		return NULL;
	}

	void *addr = mmap( NULL, size * 2, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0 );
	if ( addr == MAP_FAILED )
	{
		close( fd );
		return NULL;
	}

	if ( mmap( addr, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0 ) == MAP_FAILED )
	{
		munmap( addr, size * 2 );
		close( fd );
		return NULL;
	}

	if ( mmap( (char *)addr + size, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0 ) ==
	     MAP_FAILED )
	{
		munmap( addr, size * 2 );
		close( fd );
		return NULL;
	}

	close( fd );
	return addr;
}

static void DK_RingDestroyDoubleMapping( void *addr, size_t size )
{
	munmap( addr, size * 2 );
}
#else
static void *DK_RingAllocateMemory( size_t size )
{
	void *ptr = mmap( NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0 );
	return ( ptr == MAP_FAILED ) ? NULL : ptr;
}

static void DK_RingFreeMemory( void *addr, size_t size )
{
	munmap( addr, size );
}
#endif
#endif

static inline size_t DK_RingAlignUp( size_t n, size_t alignment )
{
	return ( n + alignment - 1 ) & ~( alignment - 1 );
}

DK_RingBuffer *DK_RingBufferCreate( size_t size )
{
	if ( size == 0 )
	{
		size = DK_RING_DEFAULT_SIZE;
	}

	DK_RingBuffer *ring = (DK_RingBuffer *)malloc( sizeof( DK_RingBuffer ) );
	if ( !ring )
	{
		return NULL;
	}

	memset( ring, 0, sizeof( DK_RingBuffer ) );

	ring->page_size = DK_RingGetSystemPageSize();

	size       = DK_RingAlignUp( size, ring->page_size );
	ring->size = size;

	ring->header_size   = DK_RingAlignUp( sizeof( DK_RingHeader ), DK_RING_MIN_ALIGNMENT );
	ring->min_alignment = DK_RING_MIN_ALIGNMENT;

#if DK_RING_DOUBLE_MAPPING
	ring->memory           = DK_RingCreateDoubleMapping( size );
	ring->is_double_mapped = true;
#else
	ring->memory           = DK_RingAllocateMemory( size );
	ring->is_double_mapped = false;
#endif

	if ( !ring->memory )
	{
		free( ring );
		return NULL;
	}

	ring->uses_virtual_memory = true;
	ring->head                = 0;
	ring->tail                = 0;
	ring->active              = 0;

#if DK_RING_THREAD_SAFE
	// TODO (David) implement thread safe implementation
	ring->mutex = NULL;
#endif

	return ring;
}

void DK_RingBufferDestroy( DK_RingBuffer *ring )
{
	if ( !ring )
	{
		return;
	}

#if DK_RING_STATS
	if ( ring->active > 0 )
	{
		fprintf( stderr, "Warning: Destroying ring buffer with %zu active allocations\n", ring->active );
		DK_RingBufferPrintStats( ring );
	}
#endif

#if DK_RING_THREAD_SAFE
	// TODO (David) implement thread safe implementation
#endif

	if ( ring->uses_virtual_memory )
	{
#if DK_RING_DOUBLE_MAPPING
		if ( ring->is_double_mapped )
		{
			DK_RingDestroyDoubleMapping( ring->memory, ring->size );
		}
		else
		{
#ifdef _WIN32
			DK_RingFreeMemory( ring->memory );
#else
			DK_RingFreeMemory( ring->memory, ring->size );
#endif
		}
#else
#ifdef _WIN32
		DK_RingFreeMemory( ring->memory );
#else
		DK_RingFreeMemory( ring->memory, ring->size );
#endif
#endif
	}
	else
	{
		free( ring->memory );
	}

	free( ring );
}

void *DK_RingBufferAllocAligned( DK_RingBuffer *ring, size_t size, size_t alignment )
{
	if ( !ring || size == 0 )
	{
		return NULL;
	}

	if ( alignment < ring->min_alignment )
	{
		alignment = ring->min_alignment;
	}

	if ( alignment & ( alignment - 1 ) )
	{
		alignment--;
		alignment |= alignment >> 1;
		alignment |= alignment >> 2;
		alignment |= alignment >> 4;
		alignment |= alignment >> 8;
		alignment |= alignment >> 16;
		alignment++;
	}

#if DK_RING_THREAD_SAFE
	// TODO (David) implement thread safe implementation
	// Lock mute
#endif

	size_t header_size  = ring->header_size;
	size_t aligned_size = DK_RingAlignUp( size, alignment );
	size_t total_size   = header_size + aligned_size;

	if ( total_size > ring->size )
	{
#if DK_RING_STATS
		ring->failed_allocations++;
#endif
#if DK_RING_THREAD_SAFE
		// TODO (David) implement thread safe implementation
		// Unlock mutex
#endif
		return NULL;
	}

	size_t available;
	if ( ring->head >= ring->tail )
	{
		available = ring->size - ring->head;
		if ( available < total_size )
		{
			if ( ring->tail > total_size )
			{
				DK_RingHeader *end_header = (DK_RingHeader *)( (char *)ring->memory + ring->head );
				end_header->magic         = DK_RING_MAGIC;
				end_header->size          = available - header_size;
				end_header->flags         = DK_RING_FLAG_PADDING;

				ring->head = 0;
#if DK_RING_STATS
				ring->wraparounds++;
#endif

				available = ring->tail;
			}
		}
	}
	else
	{
		available = ring->tail - ring->head;
	}

	if ( available < total_size )
	{
#if DK_RING_STATS
		ring->failed_allocations++;
#endif
#if DK_RING_THREAD_SAFE
		// Unlock mutex
		// TODO (David) implement thread safe implementation
#endif
		return NULL;
	}

	DK_RingHeader *header = (DK_RingHeader *)( (char *)ring->memory + ring->head );

	header->magic = DK_RING_MAGIC;
	header->size  = size;
	header->flags = DK_RING_FLAG_USED;

#if DK_RING_DEBUG
	header->file      = NULL;
	header->line      = 0;
	header->timestamp = (uint64_t)time( NULL );
#endif

	char *raw_data     = (char *)header + header_size;
	void *aligned_data = (void *)DK_RingAlignUp( (uintptr_t)raw_data, alignment );

	ring->head += total_size;

	ring->active++;
#if DK_RING_STATS
	ring->total_allocations++;
	ring->bytes_allocated += size;

	if ( size > ring->largest_allocation )
	{
		ring->largest_allocation = size;
	}

	if ( ring->bytes_allocated > ring->peak_bytes_allocated )
	{
		ring->peak_bytes_allocated = ring->bytes_allocated;
	}
#endif

#if DK_RING_THREAD_SAFE
	// Unlock mutex
	// TODO (David) implement thread safe implementation
#endif

	return aligned_data;
}

#if DK_RING_DEBUG
void *DK_RingBufferAllocDebug( DK_RingBuffer *ring, size_t size, const char *file, int line )
{
	void *ptr = DK_RingBufferAllocAligned( ring, size, ring->min_alignment );

	if ( ptr && ring )
	{
		DK_RingHeader *header = (DK_RingHeader *)( (char *)ptr - ring->header_size );

		header->file      = file;
		header->line      = line;
		header->timestamp = (uint64_t)time( NULL );
	}

	return ptr;
}
#else
void *DK_RingBufferAlloc( DK_RingBuffer *ring, size_t size )
{
	return DK_RingBufferAllocAligned( ring, size, ring->min_alignment );
}
#endif

#if DK_RING_DEBUG
void DK_RingBufferFreeDebug( DK_RingBuffer *ring, void *ptr, const char *file, int line )
{
#else
void DK_RingBufferFree( DK_RingBuffer *ring, void *ptr )
{
#endif
	if ( !ring || !ptr )
	{
		return;
	}

#if DK_RING_THREAD_SAFE
	// Lock mutex
	// TODO (David) implement thread safe implementation
#endif

	DK_RingHeader *header = (DK_RingHeader *)( (char *)ptr - ring->header_size );

	if ( header->magic != DK_RING_MAGIC )
	{
		fprintf( stderr, "Error: Invalid ring buffer block header (magic number mismatch)\n" );
		return;
	}

	if ( !( header->flags & DK_RING_FLAG_USED ) )
	{
		fprintf( stderr, "Error: Double free detected in ring buffer\n" );
#if DK_RING_DEBUG
		fprintf( stderr, "    Original allocation: %s:%d\n", header->file, header->line );
		fprintf( stderr, "    Double free attempted: %s:%d\n", file, line );
#endif
		return;
	}

	header->flags &= ~DK_RING_FLAG_USED;
	header->flags |= DK_RING_FLAG_INVALID;

	ring->active--;
#if DK_RING_STATS
	ring->bytes_allocated -= header->size;
#endif

#if DK_RING_THREAD_SAFE
	// Unlock mutex
	// TODO (David) implement thread safe implementation
#endif

#if DK_RING_DEBUG
	memset( ptr, 0xDD, header->size );
#endif
}

void DK_RingBufferReset( DK_RingBuffer *ring )
{
	if ( !ring )
	{
		return;
	}

#if DK_RING_THREAD_SAFE
	// Lock mutex
	// TODO (David) implement thread safe implementation
#endif

	ring->head   = 0;
	ring->tail   = 0;
	ring->active = 0;

#if DK_RING_STATS
	ring->bytes_allocated = 0;
#endif

#if DK_RING_THREAD_SAFE
	// Unlock mutex
	// TODO (David) implement thread safe implementation
#endif
}

size_t DK_RingBufferGetFreeSpace( DK_RingBuffer *ring )
{
	if ( !ring )
	{
		return 0;
	}

	size_t free_space;
	if ( ring->head >= ring->tail )
	{
		free_space = ( ring->size - ring->head ) + ring->tail;
	}
	else
	{
		free_space = ring->tail - ring->head;
	}

	return free_space;
}

void DK_RingBufferGetStats( DK_RingBuffer *ring, DK_RingStats *stats )
{
	if ( !ring || !stats )
	{
		return;
	}

	memset( stats, 0, sizeof( DK_RingStats ) );

	stats->total_size         = ring->size;
	stats->active_allocations = ring->active;

#if DK_RING_STATS
	stats->used_size          = ring->bytes_allocated;
	stats->utilization        = (float)ring->bytes_allocated / (float)ring->size;
	stats->total_allocations  = ring->total_allocations;
	stats->failed_allocations = ring->failed_allocations;
	stats->largest_allocation = ring->largest_allocation;
	stats->peak_memory_used   = ring->peak_bytes_allocated;
	stats->wraparounds        = ring->wraparounds;
#endif
}

void DK_RingBufferPrintStats( DK_RingBuffer *ring )
{
	if ( !ring )
	{
		return;
	}

	DK_RingStats stats;
	DK_RingBufferGetStats( ring, &stats );

	printf( "===== Ring Buffer Statistics =====\n" );
	printf( "Total memory: %zu bytes (%.2f MB)\n",
	        stats.total_size,
	        stats.total_size / ( 1024.0f * 1024.0f ) );
	printf( "Used memory: %zu bytes (%.2f MB)\n", stats.used_size, stats.used_size / ( 1024.0f * 1024.0f ) );
	printf( "Utilization: %.1f%%\n", stats.utilization * 100.0f );
	printf( "Free space: %zu bytes (%.2f MB)\n",
	        DK_RingBufferGetFreeSpace( ring ),
	        DK_RingBufferGetFreeSpace( ring ) / ( 1024.0f * 1024.0f ) );
	printf( "Active allocations: %zu\n", stats.active_allocations );

#if DK_RING_STATS
	printf( "Total allocations: %zu\n", stats.total_allocations );
	printf( "Failed allocations: %zu\n", stats.failed_allocations );
	printf( "Largest allocation: %zu bytes\n", stats.largest_allocation );
	printf( "Peak memory used: %zu bytes (%.1f%%)\n",
	        stats.peak_memory_used,
	        (float)stats.peak_memory_used / stats.total_size * 100.0f );
	printf( "Wraparounds: %zu\n", stats.wraparounds );
#endif

	printf( "=================================\n" );
}

bool DK_RingBufferValidate( DK_RingBuffer *ring )
{
	if ( !ring )
	{
		fprintf( stderr, "Error: NULL ring buffer pointer\n" );
		return false;
	}

	printf( "Validating ring buffer integrity...\n" );

	bool   valid        = true;
	size_t active_count = 0;
	size_t bytes_in_use = 0;

#if DK_RING_DOUBLE_MAPPING
	size_t scan_pos = 0;

	while ( scan_pos < ring->size )
	{
		DK_RingHeader *header = (DK_RingHeader *)( (char *)ring->memory + scan_pos );
		if ( header->magic != DK_RING_MAGIC )
		{
			break;
		}

		if ( header->flags & DK_RING_FLAG_USED )
		{
			active_count++;
			bytes_in_use += header->size;
		}

		scan_pos += ring->header_size + DK_RingAlignUp( header->size, ring->min_alignment );
		if ( scan_pos >= ring->size )
		{
			scan_pos = 0;
		}

		if ( active_count > ring->total_allocations )
		{
			fprintf( stderr, "Error: Potential cycle detected in ring buffer\n" );
			valid = false;
			break;
		}
	}
#else
	if ( ring->head > ring->size || ring->tail > ring->size )
	{
		fprintf( stderr, "Error: Invalid head/tail positions\n" );
		valid = false;
	}
#endif

	if ( active_count != ring->active )
	{
		fprintf( stderr,
		         "Error: Active count mismatch (found %zu, expected %zu)\n",
		         active_count,
		         ring->active );
		valid = false;
	}

#if DK_RING_STATS
	if ( bytes_in_use != ring->bytes_allocated )
	{
		fprintf( stderr,
		         "Error: Bytes allocated mismatch (found %zu, expected %zu)\n",
		         bytes_in_use,
		         ring->bytes_allocated );
		valid = false;
	}
#endif

	printf( "Validation %s. Found %zu active allocations using %zu bytes\n",
	        valid ? "passed" : "failed",
	        active_count,
	        bytes_in_use );

	return valid;
}

#endif // DK_RING_BUFFER_IMPLEMENTATION
#endif // DK_RING_BUFFER_H