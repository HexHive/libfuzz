#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#define TIFF_SSIZE_T int64_t
typedef void* thandle_t; 
typedef TIFF_SSIZE_T tmsize_t;
#define TIFF_TMSIZE_T_MAX (tmsize_t)(SIZE_MAX >> 1)

typedef uint64_t toff_t;

struct tiff {
	char*                tif_name;         /* name of open file */
	int                  tif_fd;           /* open file descriptor */
	int                  tif_mode;         /* open mode (O_*) */
	uint32_t               tif_flags;
	#define TIFF_FILLORDER   0x00003U /* natural bit fill order for machine */
	#define TIFF_DIRTYHEADER 0x00004U /* header must be written on close */
	#define TIFF_DIRTYDIRECT 0x00008U /* current directory must be written */
	#define TIFF_BUFFERSETUP 0x00010U /* data buffers setup */
	#define TIFF_CODERSETUP  0x00020U /* encoder/decoder setup done */
	#define TIFF_BEENWRITING 0x00040U /* written 1+ scanlines to file */
	#define TIFF_SWAB        0x00080U /* byte swap file information */
	#define TIFF_NOBITREV    0x00100U /* inhibit bit reversal logic */
	#define TIFF_MYBUFFER    0x00200U /* my raw data buffer; free on close */
	#define TIFF_ISTILED     0x00400U /* file is tile, not strip- based */
	#define TIFF_MAPPED      0x00800U /* file is mapped into memory */
	#define TIFF_POSTENCODE  0x01000U /* need call to postencode routine */
	#define TIFF_INSUBIFD    0x02000U /* currently writing a subifd */
	#define TIFF_UPSAMPLED   0x04000U /* library is doing data up-sampling */
	#define TIFF_STRIPCHOP   0x08000U /* enable strip chopping support */
	#define TIFF_HEADERONLY  0x10000U /* read header only, do not process the first directory */
	#define TIFF_NOREADRAW   0x20000U /* skip reading of raw uncompressed image data */
	#define TIFF_INCUSTOMIFD 0x40000U /* currently writing a custom IFD */
	#define TIFF_BIGTIFF     0x80000U /* read/write bigtiff */
        #define TIFF_BUF4WRITE  0x100000U /* rawcc bytes are for writing */
        #define TIFF_DIRTYSTRIP 0x200000U /* stripoffsets/stripbytecount dirty*/
        #define TIFF_PERSAMPLE  0x400000U /* get/set per sample tags as arrays */
        #define TIFF_BUFFERMMAP 0x800000U /* read buffer (tif_rawdata) points into mmap() memory */
        #define TIFF_DEFERSTRILELOAD 0x1000000U /* defer strip/tile offset/bytecount array loading. */
        #define TIFF_LAZYSTRILELOAD  0x2000000U /* lazy/ondemand loading of strip/tile offset/bytecount values. Only used if TIFF_DEFERSTRILELOAD is set and in read-only mode */
        #define TIFF_CHOPPEDUPARRAYS 0x4000000U /* set when allocChoppedUpStripArrays() has modified strip array */
	uint64_t               tif_diroff;       /* file offset of current directory */
	uint64_t               tif_nextdiroff;   /* file offset of following directory */
	uint64_t*              tif_dirlist;      /* list of offsets to already seen directories to prevent IFD looping */
	uint16_t               tif_dirlistsize;  /* number of entries in offset list */
	uint16_t               tif_dirnumber;    /* number of already seen directories */
	// TIFFDirectory        tif_dir;          /* internal rep of current directory */
	// TIFFDirectory        tif_customdir;    /* custom IFDs are separated from the main ones */
	// union {
	// 	TIFFHeaderCommon common;
	// 	TIFFHeaderClassic classic;
	// 	TIFFHeaderBig big;
	// } tif_header;
	// uint16_t               tif_header_size;  /* file's header block and its length */
	uint32_t               tif_row;          /* current scanline */
	uint16_t               tif_curdir;       /* current directory (index) */
	uint32_t               tif_curstrip;     /* current strip for read/write */
	uint64_t               tif_curoff;       /* current offset for read/write */
	uint64_t               tif_dataoff;      /* current offset for writing dir */
	/* SubIFD support */
	uint16_t               tif_nsubifd;      /* remaining subifds to write */
	uint64_t               tif_subifdoff;    /* offset for patching SubIFD link */
	/* tiling support */
	uint32_t               tif_col;          /* current column (offset by row too) */
	uint32_t               tif_curtile;      /* current tile for read/write */
	tmsize_t             tif_tilesize;     /* # of bytes in a tile */
	/* compression scheme hooks */
	int                  tif_decodestatus;
	// TIFFBoolMethod       tif_fixuptags;    /* called in TIFFReadDirectory */
	// TIFFBoolMethod       tif_setupdecode;  /* called once before predecode */
	// TIFFPreMethod        tif_predecode;    /* pre- row/strip/tile decoding */
	// TIFFBoolMethod       tif_setupencode;  /* called once before preencode */
	int                  tif_encodestatus;
	// TIFFPreMethod        tif_preencode;    /* pre- row/strip/tile encoding */
	// TIFFBoolMethod       tif_postencode;   /* post- row/strip/tile encoding */
	// TIFFCodeMethod       tif_decoderow;    /* scanline decoding routine */
	// TIFFCodeMethod       tif_encoderow;    /* scanline encoding routine */
	// TIFFCodeMethod       tif_decodestrip;  /* strip decoding routine */
	// TIFFCodeMethod       tif_encodestrip;  /* strip encoding routine */
	// TIFFCodeMethod       tif_decodetile;   /* tile decoding routine */
	// TIFFCodeMethod       tif_encodetile;   /* tile encoding routine */
	// TIFFVoidMethod       tif_close;        /* cleanup-on-close routine */
	// TIFFSeekMethod       tif_seek;         /* position within a strip routine */
	// TIFFVoidMethod       tif_cleanup;      /* cleanup state routine */
	// TIFFStripMethod      tif_defstripsize; /* calculate/constrain strip size */
	// TIFFTileMethod       tif_deftilesize;  /* calculate/constrain tile size */
	uint8_t*               tif_data;         /* compression scheme private data */
	/* input/output buffering */
	tmsize_t             tif_scanlinesize; /* # of bytes in a scanline */
	tmsize_t             tif_scanlineskew; /* scanline skew for reading strips */
	uint8_t*               tif_rawdata;      /* raw data buffer */
	tmsize_t             tif_rawdatasize;  /* # of bytes in raw data buffer */
        tmsize_t             tif_rawdataoff;   /* rawdata offset within strip */
        tmsize_t             tif_rawdataloaded;/* amount of data in rawdata */
	uint8_t*               tif_rawcp;        /* current spot in raw buffer */
	tmsize_t             tif_rawcc;        /* bytes unread from raw buffer */
	/* memory-mapped file support */
	uint8_t*               tif_base;         /* base of mapped file */
	tmsize_t             tif_size;         /* size of mapped file region (bytes, thus tmsize_t) */
	// TIFFMapFileProc      tif_mapproc;      /* map file method */
	// TIFFUnmapFileProc    tif_unmapproc;    /* unmap file method */
	/* input/output callback methods */
	thandle_t            tif_clientdata;   /* callback parameter */
	// TIFFReadWriteProc    tif_readproc;     /* read method */
	// TIFFReadWriteProc    tif_writeproc;    /* write method */
	// TIFFSeekProc         tif_seekproc;     /* lseek method */
	// TIFFCloseProc        tif_closeproc;    /* close method */
	// TIFFSizeProc         tif_sizeproc;     /* filesize method */
	/* post-decoding support */
	// TIFFPostMethod       tif_postdecode;   /* post decoding routine */
	/* tag support */
	// TIFFField**          tif_fields;       /* sorted table of registered tags */
	// size_t               tif_nfields;      /* # entries in registered tag table */
	// const TIFFField*     tif_foundfield;   /* cached pointer to already found tag */
	// TIFFTagMethods       tif_tagmethods;   /* tag get/set/print routines */
	// TIFFClientInfoLink*  tif_clientinfo;   /* extra client information. */
	/* Backward compatibility stuff. We need these two fields for
	 * setting up an old tag extension scheme. */
	// TIFFFieldArray*      tif_fieldscompat;
	// size_t               tif_nfieldscompat;
};


typedef struct tiff TIFF;

typedef void (*TIFFErrorHandler)(const char*, const char*, va_list);
typedef void (*TIFFErrorHandlerExt)(thandle_t, const char*, const char*, va_list);
typedef tmsize_t (*TIFFReadWriteProc)(thandle_t, void*, tmsize_t);
typedef toff_t (*TIFFSeekProc)(thandle_t, toff_t, int);
typedef int (*TIFFCloseProc)(thandle_t);
typedef toff_t (*TIFFSizeProc)(thandle_t);
typedef int (*TIFFMapFileProc)(thandle_t, void** base, toff_t* size);
typedef void (*TIFFUnmapFileProc)(thandle_t, void* base, toff_t size);
typedef void (*TIFFExtendProc)(TIFF*);

#define O_ACCMODE	   0003
#define O_RDONLY	     00
#define O_WRONLY	     01
#define O_RDWR		     02
#define O_CREAT	   0100	/* Not fcntl.  */
#define O_TRUNC	  01000

void
TIFFErrorExt(thandle_t fd, const char* module, const char* fmt, ...) {}

void*
_TIFFmalloc(tmsize_t s)
{
        if (s == 0)
                return ((void *) NULL);

	return (malloc((size_t) s));
}

void
_TIFFmemset(void* p, int v, tmsize_t c)
{
	memset(p, v, (size_t) c);
}

void
_TIFFfree(void* p)
{
	free(p);
}

int
_TIFFgetMode(const char* mode, const char* module)
{
	int m = -1;

	switch (mode[0]) {
	case 'r':
		m = O_RDONLY;
		if (mode[1] == '+')
			m = O_RDWR;
		break;
	case 'w':
	case 'a':
		m = O_RDWR|O_CREAT;
		if (mode[0] == 'w')
			m |= O_TRUNC;
		break;
	default:
		TIFFErrorExt(0, module, "\"%s\": Bad mode", mode);
		break;
	}
	return (m);
}

void
_TIFFSetDefaultCompressionState(TIFF* tif)
{
	// tif->tif_fixuptags = _TIFFNoFixupTags; 
	// tif->tif_decodestatus = TRUE;
	// tif->tif_setupdecode = _TIFFtrue;
	// tif->tif_predecode = _TIFFNoPreCode;
	// tif->tif_decoderow = _TIFFNoRowDecode;  
	// tif->tif_decodestrip = _TIFFNoStripDecode;
	// tif->tif_decodetile = _TIFFNoTileDecode;  
	// tif->tif_encodestatus = TRUE;
	// tif->tif_setupencode = _TIFFtrue;
	// tif->tif_preencode = _TIFFNoPreCode;
	// tif->tif_postencode = _TIFFtrue;
	// tif->tif_encoderow = _TIFFNoRowEncode;
	// tif->tif_encodestrip = _TIFFNoStripEncode;  
	// tif->tif_encodetile = _TIFFNoTileEncode;  
	// tif->tif_close = _TIFFvoid;
	// tif->tif_seek = _TIFFNoSeek;
	// tif->tif_cleanup = _TIFFvoid;
	// tif->tif_defstripsize = _TIFFDefaultStripSize;
	// tif->tif_deftilesize = _TIFFDefaultTileSize;
	tif->tif_flags &= ~(TIFF_NOBITREV|TIFF_NOREADRAW);
}

TIFF*
TIFFClientOpen(
	const char* name, const char* mode,
	thandle_t clientdata,
	TIFFReadWriteProc readproc,
	TIFFReadWriteProc writeproc,
	TIFFSeekProc seekproc,
	TIFFCloseProc closeproc,
	TIFFSizeProc sizeproc,
	TIFFMapFileProc mapproc,
	TIFFUnmapFileProc unmapproc
)
{
	static const char module[] = "TIFFClientOpen";
	TIFF *tif;
	int m;
	const char* cp;

	/* The following are configuration checks. They should be redundant, but should not
	 * compile to any actual code in an optimised release build anyway. If any of them
	 * fail, (makefile-based or other) configuration is not correct */
	assert(sizeof(uint8_t) == 1);
	assert(sizeof(int8_t) == 1);
	assert(sizeof(uint16_t) == 2);
	assert(sizeof(int16_t) == 2);
	assert(sizeof(uint32_t) == 4);
	assert(sizeof(int32_t) == 4);
	assert(sizeof(uint64_t) == 8);
	assert(sizeof(int64_t) == 8);
	assert(sizeof(tmsize_t)==sizeof(void*));
	{
		union{
			uint8_t a8[2];
			uint16_t a16;
		} n;
		n.a8[0]=1;
		n.a8[1]=0;
                (void)n;
		#ifdef WORDS_BIGENDIAN
		assert(n.a16==256);
		#else
		assert(n.a16==1);
		#endif
	}

	m = _TIFFgetMode(mode, module);
	if (m == -1)
		goto bad2;
	tif = (TIFF *)_TIFFmalloc((tmsize_t)(sizeof (TIFF) + strlen(name) + 1));
	if (tif == NULL) {
		TIFFErrorExt(clientdata, module, "%s: Out of memory (TIFF structure)", name);
		goto bad2;
	}
	_TIFFmemset(tif, 0, sizeof (*tif));
	tif->tif_name = (char *)tif + sizeof (TIFF);
	strcpy(tif->tif_name, name);
	tif->tif_mode = m &~ (O_CREAT|O_TRUNC);
	tif->tif_curdir = (uint16_t) -1;		/* non-existent directory */
	tif->tif_curoff = 0;
	tif->tif_curstrip = (uint32_t) -1;	/* invalid strip */
	tif->tif_row = (uint32_t) -1;		/* read/write pre-increment */
	tif->tif_clientdata = clientdata;
	if (!readproc || !writeproc || !seekproc || !closeproc || !sizeproc) {
		TIFFErrorExt(clientdata, module,
		    "One of the client procedures is NULL pointer.");
		_TIFFfree(tif);
		goto bad2;
	}
	// tif->tif_readproc = readproc;
	// tif->tif_writeproc = writeproc;
	// tif->tif_seekproc = seekproc;
	// tif->tif_closeproc = closeproc;
	// tif->tif_sizeproc = sizeproc;
	_TIFFSetDefaultCompressionState(tif);

    return tif;
bad2:
	return ((TIFF*)0);
}

void fun1(char* name, char* mode) {

    TIFF* tif = TIFFClientOpen(name, mode, 0, 0, 0, 0, 0, 0, 0, 0);
    tif->tif_flags = 0;
}