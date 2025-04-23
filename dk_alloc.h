/**
 * @author David Kviloria <david@skystargames.com>
 * STB Style library.
 * 
 * General purpose memory allocator
 */
#ifndef DK_ALLOCATOR_H
#define DK_ALLOCATOR_H

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

#define DK_ALLOC_DEBUG 1
#define DK_ALLOC_TRACKING 1

#define DK_ALLOC_HEADER_MAGIC 0xF00DCAFEA110CA7E
#define DK_ALLOC_FOOTER_MAGIC 0xBAADF00DFEEDFACE

#define DK_ALLOC_SIZE_CLASSES 32
#define DK_ALLOC_MIN_SIZE_CLASS 16
#define DK_ALLOC_SIZE_CLASS_GROWTH 1.25
#define DK_ALLOC_MEDIUM_CUTOFF 4096

#define DK_ALLOC_LARGE_ALIGNMENT 4096
#define DK_ALLOC_MAX_PAGES 1024 * 1024 // 4GB with 4K pages

#define DK_ALLOC_FLAG_FREE 0x0001
#define DK_ALLOC_FLAG_LARGE 0x0002
#define DK_ALLOC_FLAG_EXTERNAL 0x0004
#define DK_ALLOC_FLAG_ALIGNED 0x0008

/*
 * Memory Layout:
 * # Block Header (32B) # Padding (0-alignment) # User Data # Block Footer (16B) #
 */
typedef struct DK_AllocHeader
{
	uint64_t               magic;
	size_t                 size;
	uint16_t               flags;
	uint16_t               size_class;
	struct DK_AllocHeader *prev;
	struct DK_AllocHeader *next;

#if DK_ALLOC_TRACKING
	const char *file;
	int         line;
	uint64_t    timestamp;
#endif
} DK_AllocHeader;

typedef struct DK_AllocFooter
{
	uint64_t        magic;
	DK_AllocHeader *header;
} DK_AllocFooter;

typedef struct DK_SizeClass
{
	size_t          size;
	DK_AllocHeader *free_list;
	size_t          blocks_per_page;
	size_t          free_blocks;
	size_t          total_blocks;
} DK_SizeClass;

typedef struct DK_MemoryPage
{
	void                 *address;
	size_t                size;
	size_t                used;
	uint16_t              size_class;
	bool                  is_full;
	struct DK_MemoryPage *next;
} DK_MemoryPage;

typedef struct DK_Allocator
{
	DK_SizeClass size_classes[DK_ALLOC_SIZE_CLASSES];

	DK_MemoryPage *pages;
	DK_MemoryPage *free_pages;
	size_t         total_pages;
	size_t         active_pages;

	size_t total_allocated;
	size_t current_allocated;
	size_t peak_allocated;
	size_t total_allocations;
	size_t active_allocations;

	void  *mutex;
	size_t system_page_size;

	size_t default_alignment;
	bool   track_allocations;
	bool   zero_on_alloc;
	bool   guard_pages;
} DK_Allocator;

DK_Allocator *DK_AllocatorCreate( void );
void          DK_AllocatorDestroy( DK_Allocator *allocator );

#if DK_ALLOC_TRACKING
void *DK_AllocateDebug( DK_Allocator *allocator, size_t size, size_t alignment, const char *file, int line );
void *DK_ReallocateDebug( DK_Allocator *allocator, void *ptr, size_t size, const char *file, int line );
#define DK_Allocate( allocator, size, alignment )                                                            \
	DK_AllocateDebug( allocator, size, alignment, __FILE__, __LINE__ )
#define DK_Reallocate( allocator, ptr, size ) DK_ReallocateDebug( allocator, ptr, size, __FILE__, __LINE__ )
#else
void *DK_Allocate( DK_Allocator *allocator, size_t size, size_t alignment );
void *DK_Reallocate( DK_Allocator *allocator, void *ptr, size_t size );
#endif

void   DK_Deallocate( DK_Allocator *allocator, void *ptr );
size_t DK_GetAllocationSize( DK_Allocator *allocator, void *ptr );

typedef struct DK_MemoryStats
{
	size_t total_virtual_reserved;
	size_t total_physical_committed;
	size_t total_allocated;
	size_t current_allocated;
	size_t peak_allocated;
	size_t total_allocations;
	size_t active_allocations;
	size_t fragmentation_percent;
} DK_MemoryStats;

void DK_GetMemoryStats( DK_Allocator *allocator, DK_MemoryStats *stats );
void DK_DumpMemoryStats( DK_Allocator *allocator );
void DK_DumpLeaks( DK_Allocator *allocator );

static size_t DK_GetSystemPageSize( void );
static void  *DK_ReserveAddressSpace( size_t size );
static bool   DK_CommitMemory( void *address, size_t size );
static bool   DK_DecommitMemory( void *address, size_t size );
static void   DK_ReleaseAddressSpace( void *address, size_t size );

#if defined( DK_ALLOCATOR_IMPLEMENTATION )

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
static size_t DK_GetSystemPageSize( void )
{
	SYSTEM_INFO si;
	GetSystemInfo( &si );
	return si.dwPageSize;
}

static void *DK_ReserveAddressSpace( size_t size )
{
	return VirtualAlloc( NULL, size, MEM_RESERVE, PAGE_NOACCESS );
}

static bool DK_CommitMemory( void *address, size_t size )
{
	return VirtualAlloc( address, size, MEM_COMMIT, PAGE_READWRITE ) != NULL;
}

static bool DK_DecommitMemory( void *address, size_t size )
{
	return VirtualFree( address, size, MEM_DECOMMIT );
}

static void DK_ReleaseAddressSpace( void *address, size_t size )
{
	VirtualFree( address, 0, MEM_RELEASE );
}
#else

static size_t DK_GetSystemPageSize( void )
{
	return (size_t)sysconf( _SC_PAGESIZE );
}

static void *DK_ReserveAddressSpace( size_t size )
{
	void *ptr = mmap( NULL, size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0 );
	return ( ptr == MAP_FAILED ) ? NULL : ptr;
}

static bool DK_CommitMemory( void *address, size_t size )
{
	return mprotect( address, size, PROT_READ | PROT_WRITE ) == 0;
}

static bool DK_DecommitMemory( void *address, size_t size )
{
	return mmap( address, size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0 ) != MAP_FAILED;
}

static void DK_ReleaseAddressSpace( void *address, size_t size )
{
	munmap( address, size );
}
#endif

static inline size_t DK_AlignUp( size_t n, size_t alignment )
{
	return ( n + alignment - 1 ) & ~( alignment - 1 );
}

static inline size_t DK_GetTotalSize( size_t size, size_t alignment )
{
	size_t header_size = DK_AlignUp( sizeof( DK_AllocHeader ), alignment );
	size_t footer_size = sizeof( DK_AllocFooter );
	return header_size + size + footer_size;
}

static inline DK_AllocHeader *DK_GetHeader( void *ptr )
{
	return (DK_AllocHeader *)( (char *)ptr - sizeof( DK_AllocHeader ) );
}

static inline DK_AllocFooter *DK_GetFooter( DK_AllocHeader *header )
{
	return (DK_AllocFooter *)( (char *)( header + 1 ) + header->size );
}

static inline void *DK_GetUserPtr( DK_AllocHeader *header )
{
	return (void *)( header + 1 );
}

static void DK_InitSizeClasses( DK_Allocator *allocator )
{
	size_t size = DK_ALLOC_MIN_SIZE_CLASS;

	for ( int i = 0; i < DK_ALLOC_SIZE_CLASSES; i++ )
	{
		allocator->size_classes[i].size      = size;
		allocator->size_classes[i].free_list = NULL;
		allocator->size_classes[i].blocks_per_page =
		    ( allocator->system_page_size - sizeof( DK_MemoryPage ) ) /
		    DK_GetTotalSize( size, allocator->default_alignment );
		allocator->size_classes[i].free_blocks  = 0;
		allocator->size_classes[i].total_blocks = 0;

		size = (size_t)( size * DK_ALLOC_SIZE_CLASS_GROWTH );

		if ( size < DK_ALLOC_MIN_SIZE_CLASS * ( i + 1 ) )
		{
			size = DK_ALLOC_MIN_SIZE_CLASS * ( i + 1 );
		}

		size = DK_AlignUp( size, allocator->default_alignment );
	}
}

static int DK_GetSizeClass( DK_Allocator *allocator, size_t size )
{
	if ( size > allocator->size_classes[DK_ALLOC_SIZE_CLASSES - 1].size )
	{
		return -1;
	}

	for ( int i = 0; i < DK_ALLOC_SIZE_CLASSES; i++ )
	{
		if ( size <= allocator->size_classes[i].size )
		{
			return i;
		}
	}

	return -1;
}

static DK_MemoryPage *DK_AllocatePage( DK_Allocator *allocator, int size_class_index )
{
	DK_SizeClass *size_class = &allocator->size_classes[size_class_index];
	size_t        page_size  = allocator->system_page_size;

	if ( allocator->free_pages )
	{
		DK_MemoryPage *page   = allocator->free_pages;
		allocator->free_pages = page->next;
		page->size_class      = size_class_index;
		page->used            = 0;
		page->is_full         = false;
		return page;
	}

	void *page_addr = DK_ReserveAddressSpace( page_size );
	if ( !page_addr )
	{
		return NULL;
	}

	if ( !DK_CommitMemory( page_addr, page_size ) )
	{
		DK_ReleaseAddressSpace( page_addr, page_size );
		return NULL;
	}

	DK_MemoryPage *page = (DK_MemoryPage *)page_addr;
	page->address       = page_addr;
	page->size          = page_size;
	page->used          = sizeof( DK_MemoryPage );
	page->size_class    = size_class_index;
	page->is_full       = false;
	page->next          = allocator->pages;
	allocator->pages    = page;

	allocator->total_pages++;
	allocator->active_pages++;

	size_t block_size      = DK_GetTotalSize( size_class->size, allocator->default_alignment );
	size_t available_space = page_size - sizeof( DK_MemoryPage );
	size_t num_blocks      = available_space / block_size;

	char *block_start = (char *)page_addr + sizeof( DK_MemoryPage );

	for ( size_t i = 0; i < num_blocks; i++ )
	{
		DK_AllocHeader *header = (DK_AllocHeader *)block_start;

		header->magic      = DK_ALLOC_HEADER_MAGIC;
		header->size       = size_class->size;
		header->flags      = DK_ALLOC_FLAG_FREE;
		header->size_class = size_class_index;
		header->prev       = NULL;
		header->next       = size_class->free_list;

		if ( size_class->free_list )
		{
			size_class->free_list->prev = header;
		}

		DK_AllocFooter *footer = (DK_AllocFooter *)( block_start + block_size - sizeof( DK_AllocFooter ) );
		footer->magic          = DK_ALLOC_FOOTER_MAGIC;
		footer->header         = header;

		size_class->free_list = header;
		size_class->free_blocks++;
		size_class->total_blocks++;

		block_start += block_size;
	}

	return page;
}

static void *DK_AllocateLarge( DK_Allocator *allocator, size_t size, size_t alignment )
{
	size_t total_size = DK_GetTotalSize( size, alignment );
	total_size        = DK_AlignUp( total_size, allocator->system_page_size );

	void *block_addr = DK_ReserveAddressSpace( total_size );
	if ( !block_addr )
	{
		return NULL;
	}

	if ( !DK_CommitMemory( block_addr, total_size ) )
	{
		DK_ReleaseAddressSpace( block_addr, total_size );
		return NULL;
	}

	DK_AllocHeader *header = (DK_AllocHeader *)block_addr;
	header->magic          = DK_ALLOC_HEADER_MAGIC;
	header->size           = size;
	header->flags          = DK_ALLOC_FLAG_LARGE;
	header->size_class     = 0; // large allocation
	header->prev           = NULL;
	header->next           = NULL;

#if DK_ALLOC_TRACKING
	header->file      = NULL;
	header->line      = 0;
	header->timestamp = (uint64_t)time( NULL );
#endif

	DK_AllocFooter *footer = (DK_AllocFooter *)( (char *)block_addr + total_size - sizeof( DK_AllocFooter ) );
	footer->magic          = DK_ALLOC_FOOTER_MAGIC;
	footer->header         = header;

	allocator->total_allocated += total_size;
	allocator->current_allocated += total_size;
	allocator->total_allocations++;
	allocator->active_allocations++;

	if ( allocator->current_allocated > allocator->peak_allocated )
	{
		allocator->peak_allocated = allocator->current_allocated;
	}

	return DK_GetUserPtr( header );
}

DK_Allocator *DK_AllocatorCreate( void )
{
	DK_Allocator *allocator = malloc( sizeof( DK_Allocator ) );
	if ( !allocator )
	{
		return NULL;
	}

	memset( allocator, 0, sizeof( DK_Allocator ) );
	allocator->system_page_size = DK_GetSystemPageSize();

	allocator->default_alignment = 16; // for SIMD alignment
	allocator->track_allocations = DK_ALLOC_TRACKING;
	allocator->zero_on_alloc     = false;
	allocator->guard_pages       = false;

	DK_InitSizeClasses( allocator );

	return allocator;
}

void DK_AllocatorDestroy( DK_Allocator *allocator )
{
	if ( !allocator )
	{
		return;
	}

#if DK_ALLOC_DEBUG
	if ( allocator->active_allocations > 0 )
	{
		fprintf( stderr, "Memory leak detected: %zu active allocations\n", allocator->active_allocations );
		DK_DumpLeaks( allocator );
	}
#endif

	DK_MemoryPage *page = allocator->pages;
	while ( page )
	{
		DK_MemoryPage *next = page->next;
		DK_ReleaseAddressSpace( page->address, page->size );
		page = next;
	}

	free( allocator );
}

#if DK_ALLOC_TRACKING
void *DK_AllocateDebug( DK_Allocator *allocator, size_t size, size_t alignment, const char *file, int line )
{
#else

void *DK_Allocate( DK_Allocator *allocator, size_t size, size_t alignment )
{
#endif
	if ( !allocator || size == 0 )
	{
		return NULL;
	}

	if ( size < 1 )
		size = 1;
	if ( alignment < allocator->default_alignment )
	{
		alignment = allocator->default_alignment;
	}
	else
	{
		alignment = (size_t)1 << ( 31 - __builtin_clz( (unsigned int)alignment ) );
	}

	if ( size > allocator->size_classes[DK_ALLOC_SIZE_CLASSES - 1].size )
	{
		void *ptr = DK_AllocateLarge( allocator, size, alignment );

#if DK_ALLOC_TRACKING
		if ( ptr )
		{
			DK_AllocHeader *header = DK_GetHeader( ptr );
			header->file           = file;
			header->line           = line;
			header->timestamp      = (uint64_t)time( NULL );
		}
#endif

		return ptr;
	}

	int size_class_index = DK_GetSizeClass( allocator, size );
	if ( size_class_index < 0 )
	{
		return NULL;
	}

	DK_SizeClass *size_class = &allocator->size_classes[size_class_index];
	if ( !size_class->free_list )
	{
		if ( !DK_AllocatePage( allocator, size_class_index ) )
		{
			return NULL;
		}

		if ( !size_class->free_list )
		{
			return NULL;
		}
	}

	DK_AllocHeader *header = size_class->free_list;
	size_class->free_list  = header->next;

	if ( size_class->free_list )
	{
		size_class->free_list->prev = NULL;
	}

	header->flags &= ~DK_ALLOC_FLAG_FREE;
	size_class->free_blocks--;

#if DK_ALLOC_TRACKING
	header->file      = file;
	header->line      = line;
	header->timestamp = (uint64_t)time( NULL );
#endif

	size_t block_size = DK_GetTotalSize( size_class->size, alignment );
	allocator->total_allocated += block_size;
	allocator->current_allocated += block_size;
	allocator->total_allocations++;
	allocator->active_allocations++;

	if ( allocator->current_allocated > allocator->peak_allocated )
	{
		allocator->peak_allocated = allocator->current_allocated;
	}

	void *user_ptr = DK_GetUserPtr( header );
	if ( allocator->zero_on_alloc )
	{
		memset( user_ptr, 0, size_class->size );
	}

	return user_ptr;
}

void DK_Deallocate( DK_Allocator *allocator, void *ptr )
{
	if ( !allocator || !ptr )
	{
		return;
	}

	DK_AllocHeader *header = DK_GetHeader( ptr );
	if ( header->magic != DK_ALLOC_HEADER_MAGIC )
	{
		fprintf( stderr,
		         "DK_Deallocate: Invalid header magic (corrupted memory or "
		         "double free)\n" );
		return;
	}

	if ( header->flags & DK_ALLOC_FLAG_FREE )
	{
		fprintf( stderr, "DK_Deallocate: Double free detected\n" );
		return;
	}

	DK_AllocFooter *footer = DK_GetFooter( header );
	if ( footer->magic != DK_ALLOC_FOOTER_MAGIC || footer->header != header )
	{
		fprintf( stderr, "DK_Deallocate: Invalid footer (memory corruption)\n" );
		return;
	}

	if ( header->flags & DK_ALLOC_FLAG_LARGE )
	{
		size_t total_size = DK_AlignUp( DK_GetTotalSize( header->size, allocator->default_alignment ),
		                                allocator->system_page_size );

		allocator->current_allocated -= total_size;
		allocator->active_allocations--;

		DK_ReleaseAddressSpace( header, total_size );
		return;
	}

	int           size_class_index = header->size_class;
	DK_SizeClass *size_class       = &allocator->size_classes[size_class_index];

	header->flags |= DK_ALLOC_FLAG_FREE;

	header->next = size_class->free_list;
	header->prev = NULL;

	if ( size_class->free_list )
	{
		size_class->free_list->prev = header;
	}

	size_class->free_list = header;
	size_class->free_blocks++;

	size_t block_size = DK_GetTotalSize( size_class->size, allocator->default_alignment );
	allocator->current_allocated -= block_size;
	allocator->active_allocations--;

#if DK_ALLOC_DEBUG
	memset( ptr, 0xDD, header->size );
#endif
}

size_t DK_GetAllocationSize( DK_Allocator *allocator, void *ptr )
{
	if ( !allocator || !ptr )
	{
		return 0;
	}

	DK_AllocHeader *header = DK_GetHeader( ptr );
	if ( header->magic != DK_ALLOC_HEADER_MAGIC )
	{
		fprintf( stderr, "DK_GetAllocationSize: Invalid header magic\n" );
		return 0;
	}

	return header->size;
}

#if DK_ALLOC_TRACKING
void *DK_ReallocateDebug( DK_Allocator *allocator, void *ptr, size_t size, const char *file, int line )
{
#else

void *DK_Reallocate( DK_Allocator *allocator, void *ptr, size_t size )
{
#endif
	if ( !allocator )
	{
		return NULL;
	}

	if ( !ptr )
	{
#if DK_ALLOC_TRACKING
		return DK_AllocateDebug( allocator, size, allocator->default_alignment, file, line );
#else
		return DK_Allocate( allocator, size, allocator->default_alignment );
#endif
	}

	if ( size == 0 )
	{
		DK_Deallocate( allocator, ptr );
		return NULL;
	}

	DK_AllocHeader *header = DK_GetHeader( ptr );
	if ( header->magic != DK_ALLOC_HEADER_MAGIC )
	{
		fprintf( stderr, "DK_Reallocate: Invalid header magic\n" );
		return NULL;
	}

	if ( header->size >= size &&
	     ( !header->size_class || size > allocator->size_classes[header->size_class - 1].size ) )
	{
		return ptr;
	}

#if DK_ALLOC_TRACKING
	void *new_ptr = DK_AllocateDebug( allocator, size, allocator->default_alignment, file, line );
#else
	void *new_ptr = DK_Allocate( allocator, size, allocator->default_alignment );
#endif

	if ( !new_ptr )
	{
		return NULL;
	}

	size_t copy_size = ( header->size < size ) ? header->size : size;
	memcpy( new_ptr, ptr, copy_size );

	DK_Deallocate( allocator, ptr );

	return new_ptr;
}

void DK_GetMemoryStats( DK_Allocator *allocator, DK_MemoryStats *stats )
{
	if ( !allocator || !stats )
	{
		return;
	}

	memset( stats, 0, sizeof( DK_MemoryStats ) );

	stats->total_virtual_reserved   = allocator->total_pages * allocator->system_page_size;
	stats->total_physical_committed = stats->total_virtual_reserved;
	stats->total_allocated          = allocator->total_allocated;
	stats->current_allocated        = allocator->current_allocated;
	stats->peak_allocated           = allocator->peak_allocated;
	stats->total_allocations        = allocator->total_allocations;
	stats->active_allocations       = allocator->active_allocations;

	if ( stats->total_physical_committed > 0 )
	{
		stats->fragmentation_percent = ( stats->total_physical_committed - stats->current_allocated ) * 100 /
		                               stats->total_physical_committed;
	}
}

void DK_DumpMemoryStats( DK_Allocator *allocator )
{
	if ( !allocator )
	{
		return;
	}

	DK_MemoryStats stats;
	DK_GetMemoryStats( allocator, &stats );

	printf( "===== Memory Allocator Statistics =====\n" );
	printf( "Virtual memory reserved: %zu MB\n", stats.total_virtual_reserved / ( 1024 * 1024 ) );
	printf( "Physical memory committed: %zu MB\n", stats.total_physical_committed / ( 1024 * 1024 ) );
	printf( "Total memory allocated: %zu MB\n", stats.total_allocated / ( 1024 * 1024 ) );
	printf( "Current memory allocated: %zu MB\n", stats.current_allocated / ( 1024 * 1024 ) );
	printf( "Peak memory allocated: %zu MB\n", stats.peak_allocated / ( 1024 * 1024 ) );
	printf( "Total allocations: %zu\n", stats.total_allocations );
	printf( "Active allocations: %zu\n", stats.active_allocations );
	printf( "Memory fragmentation: %zu%%\n", stats.fragmentation_percent );

	printf( "\nSize Class Statistics:\n" );
	printf( "Class\tSize\tBlocks\tFree\tUsage\n" );
	for ( int i = 0; i < DK_ALLOC_SIZE_CLASSES; i++ )
	{
		DK_SizeClass *sc    = &allocator->size_classes[i];
		float         usage = ( sc->total_blocks > 0 )
		                          ? ( (float)( sc->total_blocks - sc->free_blocks ) / sc->total_blocks * 100.0f )
		                          : 0.0f;
		printf( "%2d\t%5zu\t%5zu\t%5zu\t%.1f%%\n", i, sc->size, sc->total_blocks, sc->free_blocks, usage );
	}
	printf( "=======================================\n" );
}

void DK_DumpLeaks( DK_Allocator *allocator )
{
	if ( !allocator )
	{
		return;
	}

#if DK_ALLOC_TRACKING
	printf( "===== Memory Leak Report =====\n" );

	size_t total_leaks        = 0;
	size_t total_leaked_bytes = 0;

	DK_MemoryPage *page = allocator->pages;
	while ( page )
	{
		if ( page->size_class < DK_ALLOC_SIZE_CLASSES )
		{
			DK_SizeClass *size_class = &allocator->size_classes[page->size_class];
			size_t        block_size = DK_GetTotalSize( size_class->size, allocator->default_alignment );
			size_t        num_blocks = ( page->size - sizeof( DK_MemoryPage ) ) / block_size;

			char *block_start = (char *)page + sizeof( DK_MemoryPage );
			for ( size_t i = 0; i < num_blocks; i++ )
			{
				DK_AllocHeader *header = (DK_AllocHeader *)block_start;

				if ( header->magic == DK_ALLOC_HEADER_MAGIC && !( header->flags & DK_ALLOC_FLAG_FREE ) )
				{

					printf( "Leak: %zu bytes at %p", header->size, DK_GetUserPtr( header ) );

					if ( header->file )
					{
						printf( " allocated in %s line %d", header->file, header->line );
					}
					printf( "\n" );

					total_leaks++;
					total_leaked_bytes += header->size;
				}

				block_start += block_size;
			}
		}

		page = page->next;
	}

	printf( "Total leaks: %zu\n", total_leaks );
	printf( "Total leaked bytes: %zu (%zu KB)\n", total_leaked_bytes, total_leaked_bytes / 1024 );
	printf( "==============================\n" );
#else
	printf( "Leak tracking not enabled. Define DK_ALLOC_TRACKING to enable.\n" );
#endif
}

#endif

#endif