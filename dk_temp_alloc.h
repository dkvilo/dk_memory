/**
 * @author David Kviloria <david@skystargames.com>
 * STB Style library.
 */
#ifndef DK_TEMP_ALLOCATOR_H
#define DK_TEMP_ALLOCATOR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>
#endif

#define DK_TEMP_DEFAULT_SIZE ( 16 * 1024 * 1024 ) // 16MB
#define DK_TEMP_MIN_ALIGNMENT 16
#define DK_TEMP_MAX_MARKERS 64
#define DK_TEMP_OVERFLOW_HANDLER 0
#define DK_TEMP_TRACKING 1

typedef size_t DK_TempMarker;

typedef struct DK_TempBlock
{
	void  *memory;
	size_t size;
	size_t used;
	size_t high_water_mark;
	size_t min_alignment;

	// scoped allocations
	struct
	{
		DK_TempMarker positions[DK_TEMP_MAX_MARKERS];
		size_t        count;
	} markers;

	struct
	{
		size_t allocation_count;
		size_t reset_count;
		size_t overflow_count;
	} stats;

	struct
	{
		void **blocks;
		size_t count;
		size_t capacity;
	} overflow;

} DK_TempAllocator;

DK_TempAllocator *DK_TempCreate( size_t size );
void              DK_TempDestroy( DK_TempAllocator *temp );

void *DK_TempAlloc( DK_TempAllocator *temp, size_t size );
void *DK_TempAllocAligned( DK_TempAllocator *temp, size_t size, size_t alignment );

void DK_TempReset( DK_TempAllocator *temp );

DK_TempMarker DK_TempGetMarker( DK_TempAllocator *temp );
void          DK_TempFreeToMarker( DK_TempAllocator *temp, DK_TempMarker marker );

#define DK_TEMP_SCOPE_BEGIN( temp )                                                                          \
	{                                                                                                        \
		DK_TempMarker _scope_marker = DK_TempGetMarker( temp );
#define DK_TEMP_SCOPE_END( temp )                                                                            \
	DK_TempFreeToMarker( temp, _scope_marker );                                                              \
	}

typedef struct DK_TempStats
{
	size_t total_size;
	size_t used_size;
	size_t peak_size;
	float  utilization;
	size_t allocation_count;
	size_t reset_count;
	size_t overflow_count;
	size_t overflow_size;
} DK_TempStats;

void DK_TempGetStats( DK_TempAllocator *temp, DK_TempStats *stats );
void DK_TempPrintStats( DK_TempAllocator *temp );

#ifdef DK_TEMP_ALLOCATOR_IMPLEMENTATION

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static inline size_t DK_TempAlignUp( size_t n, size_t alignment )
{
	return ( n + alignment - 1 ) & ~( alignment - 1 );
}

static inline bool DK_TempIsAligned( void *ptr, size_t alignment )
{
	return ( ( (uintptr_t)ptr ) & ( alignment - 1 ) ) == 0;
}

#ifdef _WIN32
static void *DK_TempReserveAndCommitMemory( size_t size )
{
	return VirtualAlloc( NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );
}

static void DK_TempFreeMemory( void *ptr )
{
	VirtualFree( ptr, 0, MEM_RELEASE );
}
#else
static void *DK_TempReserveAndCommitMemory( size_t size )
{
	void *ptr = mmap( NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0 );
	return ( ptr == MAP_FAILED ) ? NULL : ptr;
}

static void DK_TempFreeMemory( void *ptr, size_t size )
{
	munmap( ptr, size );
}
#endif

DK_TempAllocator *DK_TempCreate( size_t size )
{
	if ( size == 0 )
	{
		size = DK_TEMP_DEFAULT_SIZE;
	}

	size_t page_size;
#ifdef _WIN32
	SYSTEM_INFO si;
	GetSystemInfo( &si );
	page_size = si.dwPageSize;
#else
	page_size = (size_t)sysconf( _SC_PAGESIZE );
#endif

	size                   = DK_TempAlignUp( size, page_size );
	DK_TempAllocator *temp = (DK_TempAllocator *)malloc( sizeof( DK_TempAllocator ) );
	if ( !temp )
	{
		return NULL;
	}

	memset( temp, 0, sizeof( DK_TempAllocator ) );
	temp->memory = DK_TempReserveAndCommitMemory( size );
	if ( !temp->memory )
	{
		free( temp );
		return NULL;
	}

	temp->size            = size;
	temp->used            = 0;
	temp->high_water_mark = 0;
	temp->min_alignment   = DK_TEMP_MIN_ALIGNMENT;

#if DK_TEMP_OVERFLOW_HANDLER
	temp->overflow.capacity = 16; // Start with space for 16 overflow blocks
	temp->overflow.blocks   = (void **)malloc( sizeof( void * ) * temp->overflow.capacity );
	temp->overflow.count    = 0;
#endif

	return temp;
}

void DK_TempDestroy( DK_TempAllocator *temp )
{
	if ( !temp )
	{
		return;
	}

#ifdef _WIN32
	DK_TempFreeMemory( temp->memory );
#else
	DK_TempFreeMemory( temp->memory, temp->size );
#endif

#if DK_TEMP_OVERFLOW_HANDLER
	for ( size_t i = 0; i < temp->overflow.count; i++ )
	{
		free( temp->overflow.blocks[i] );
	}
	free( temp->overflow.blocks );
#endif

	free( temp );
}

void *DK_TempAlloc( DK_TempAllocator *temp, size_t size )
{
	return DK_TempAllocAligned( temp, size, temp->min_alignment );
}

void *DK_TempAllocAligned( DK_TempAllocator *temp, size_t size, size_t alignment )
{
	if ( !temp || size == 0 )
	{
		return NULL;
	}

	temp->stats.allocation_count++;
	if ( alignment < temp->min_alignment )
	{
		alignment = temp->min_alignment;
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

	size_t aligned_pos = DK_TempAlignUp( temp->used, alignment );

	if ( aligned_pos + size <= temp->size )
	{
		void *ptr  = (char *)temp->memory + aligned_pos;
		temp->used = aligned_pos + size;
		if ( temp->used > temp->high_water_mark )
		{
			temp->high_water_mark = temp->used;
		}

		return ptr;
	}

#if DK_TEMP_OVERFLOW_HANDLER
	temp->stats.overflow_count++;

	size_t alloc_size = size + alignment;
	void  *raw_ptr    = malloc( alloc_size );
	if ( !raw_ptr )
	{
		return NULL;
	}

	void *aligned_ptr = (void *)DK_TempAlignUp( (uintptr_t)raw_ptr, alignment );

	if ( temp->overflow.count >= temp->overflow.capacity )
	{
		temp->overflow.capacity *= 2;
		void **new_blocks =
		    (void **)realloc( temp->overflow.blocks, sizeof( void * ) * temp->overflow.capacity );
		if ( !new_blocks )
		{
			free( raw_ptr );
			return NULL;
		}
		temp->overflow.blocks = new_blocks;
	}

	temp->overflow.blocks[temp->overflow.count++] = raw_ptr;

	return aligned_ptr;
#else
	return NULL;
#endif
}

void DK_TempReset( DK_TempAllocator *temp )
{
	if ( !temp )
	{
		return;
	}

	temp->used = 0;

	temp->markers.count = 0;

	temp->stats.reset_count++;

#if DK_TEMP_OVERFLOW_HANDLER
	for ( size_t i = 0; i < temp->overflow.count; i++ )
	{
		free( temp->overflow.blocks[i] );
	}
	temp->overflow.count = 0;
#endif
}

DK_TempMarker DK_TempGetMarker( DK_TempAllocator *temp )
{
	if ( !temp )
	{
		return 0;
	}

	if ( temp->markers.count < DK_TEMP_MAX_MARKERS )
	{
		temp->markers.positions[temp->markers.count] = temp->used;
		return temp->markers.count++;
	}

	return (DK_TempMarker)-1;
}

void DK_TempFreeToMarker( DK_TempAllocator *temp, DK_TempMarker marker )
{
	if ( !temp || marker >= temp->markers.count )
	{
		return;
	}

	size_t position = temp->markers.positions[marker];

#if DK_TEMP_OVERFLOW_HANDLER
#endif

	temp->used          = position;
	temp->markers.count = marker;
}

void DK_TempGetStats( DK_TempAllocator *temp, DK_TempStats *stats )
{
	if ( !temp || !stats )
	{
		return;
	}

	memset( stats, 0, sizeof( DK_TempStats ) );

	stats->total_size       = temp->size;
	stats->used_size        = temp->used;
	stats->peak_size        = temp->high_water_mark;
	stats->utilization      = (float)temp->used / (float)temp->size;
	stats->allocation_count = temp->stats.allocation_count;
	stats->reset_count      = temp->stats.reset_count;
	stats->overflow_count   = temp->stats.overflow_count;

#if DK_TEMP_OVERFLOW_HANDLER
	for ( size_t i = 0; i < temp->overflow.count; i++ )
	{
		// TODO (David) implement tracking of each overflow
	}
#endif
}

void DK_TempPrintStats( DK_TempAllocator *temp )
{
	if ( !temp )
	{
		return;
	}

	DK_TempStats stats;
	DK_TempGetStats( temp, &stats );

	printf( "===== Temporary Allocator Stats =====\n" );
	printf( "Total size: %.2f MB\n", stats.total_size / ( 1024.0f * 1024.0f ) );
	printf( "Used size: %.2f MB (%.1f%%)\n",
	        stats.used_size / ( 1024.0f * 1024.0f ),
	        stats.utilization * 100.0f );
	printf( "Peak usage: %.2f MB (%.1f%%)\n",
	        stats.peak_size / ( 1024.0f * 1024.0f ),
	        (float)stats.peak_size / stats.total_size * 100.0f );
	printf( "Allocations: %zu\n", stats.allocation_count );
	printf( "Resets: %zu\n", stats.reset_count );
	printf( "Overflow allocations: %zu\n", stats.overflow_count );
	printf( "===================================\n" );
}

#endif // DK_TEMP_ALLOCATOR_IMPLEMENTATION
#endif // DK_TEMP_ALLOCATOR_H