#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h> // for mkdir
#include <sys/mman.h> // for mmap

uint64_t pos = 0;

int g_list = 0;
int g_verbose = 0;
char *g_extract = NULL;

#pragma pack(1)
typedef struct mapped_file_entry
{
  char magic[6]; // magic is "070707"
  char maybe_sequential_id[12];
  char mode[6];
  char who_knows[24];
  char timestamp[10];
  char wtf_is_this[2];
  char name_size[5];
  char size[11];
  char data[0];
} mapped_file_entry_t;

typedef struct file_entry {
  mapped_file_entry_t* mentry;
  unsigned long maybe_sequential_id;
  mode_t mode;
  int timestamp;
  char* name;
  size_t name_size;
  char const* content;
  size_t size;
} file_entry_t;

void fail(char* msg) {
  printf("FAIL - %s\n", msg);
  exit(1);
}

#define MAGIC "070707"
#define MAGIC_SIZE (sizeof(MAGIC) - 1)
#define IS_MAGIC(m) (memcmp(m, MAGIC, MAGIC_SIZE) == 0)

#define TRAILER "TRAILER!!!"
#define TRAILER_SIZE (sizeof(TRAILER) - 1)
#define IS_TRAILER(m) (memcmp(m, TRAILER, TRAILER_SIZE) == 0)

static unsigned long strntol(char const* str, size_t size, int base) {
  char scratch[64];

  memcpy(scratch, str, size);
  scratch[size] = 0;
  return strtol(scratch, NULL, base);
}

static unsigned long strntoul(char const* str, size_t size, int base) {
  char scratch[64];

  memcpy(scratch, str, size);
  scratch[size] = 0;
  return strtoul(scratch, NULL, base);
}

void free_entry(file_entry_t* entry) {
  free(entry->name);
}

uint8_t* read_entry(file_entry_t* entry, void* addr) {
  mapped_file_entry_t* mentry = addr;

#ifdef DEBUG
  puts("====================== ENTRY ======================");
  printf("FULLENTRY: %.76s\n", (char*)addr);
  printf("ENTRY_SIZE: %lu\n", sizeof(mapped_file_entry_t));
#endif

  entry->mentry = mentry;
  if (!IS_MAGIC(mentry->magic)) {
    fail("Wrong magic");
  }

#ifdef DEBUG
  printf("MENTRY:\nID: %.11s\nmode: %.6s\nwho_knows: %.24s\ntimestamp: %.10s\nwtf_is_this: %.2s\nname_size: %.5s\nsize: %.11s\n",
      mentry->maybe_sequential_id,
      mentry->mode,
      mentry->who_knows,
      mentry->timestamp,
      mentry->wtf_is_this,
      mentry->name_size,
      mentry->size);
  puts("============================");
#endif
  entry->maybe_sequential_id = strntoul(mentry->maybe_sequential_id, sizeof(mentry->maybe_sequential_id), 10);
  entry->mode = strntoul(mentry->mode, sizeof(mentry->mode), 8);
  entry->timestamp = strntol(mentry->timestamp, sizeof(mentry->timestamp), 10);
  entry->name_size = strntoul(mentry->name_size, sizeof(mentry->name_size), 8);
  entry->name = strndup(mentry->data, entry->name_size);
  entry->size = strntoul(mentry->size, sizeof(mentry->size), 8);
  entry->content = mentry->data + entry->name_size;
  if (g_verbose) {
    printf("ID: %010lu mode: %06o timestamp: %i name_size: %05lu size: %011lu name: %s\n",
        entry->maybe_sequential_id,
        entry->mode,
        entry->timestamp,
        entry->name_size,
        entry->size,
        entry->name
    );
  }
  // If we reached the last entry
  if (IS_TRAILER(entry->name)) {
    return NULL;
  }
  uint8_t* next_entry = (uint8_t*)entry->content + entry->size;
  if (!IS_MAGIC(next_entry)) {
    uint8_t* old_next = next_entry;
    while (!IS_MAGIC(next_entry)) {
      ++next_entry;
    }
    size_t skipped_bytes = next_entry - old_next;
    if (g_verbose) {
      printf("Wrong magic, skipped %lu bytes.\n", skipped_bytes);
    }
    // Patching size...
    entry->size += skipped_bytes;
  }
  return next_entry;
}

void read_entries(void* start) {
  file_entry_t entry;
  uint8_t* cur = start + 1951062439;

  while (cur != NULL) {
#ifdef DEBUG
    printf("OFFSET: %lu\n", cur - (uint8_t*)start);
#endif
    cur = read_entry(&entry, cur);
    //printf("%.24s\n", (uint8_t*)entry.mentry->who_knows);
    write(1, entry.mentry->who_knows, 24);
    write(1, "\n", 1);
    free_entry(&entry);
  }
}

int main(int argc ,char **argv)
{
  char *name ="p";
  int i = 0;

  if (argc < 2) {
    fprintf (stderr,"Usage: %s [-v] [-l] [-e file] _name_\nWhere: -l: list files in update payload\n       -e _file: extract file from update payload (use \"*\" for all files)\n", argv[0]);
    exit(10);
  }

  for (i = 1; i < argc - 1; i++)
  {
  // This is super quick/dirty. You might want to rewrite with getopt, etc..
    if (strcmp (argv[i], "-l") == 0) { g_list++;} 
    if (strcmp (argv[i] , "-v") == 0) { g_verbose++;}
    if (strcmp (argv[i], "-e") == 0) { g_extract = argv[i+1]; i++;}
  }

  name = argv[argc - 1];

  int fd = open (name, O_RDONLY);
  if (fd < 0) { perror (name); exit(1);}

  struct stat stbuf;
  if (fstat(fd, &stbuf) != 0) {
    fail("fstat");
  }
  if (g_verbose) {
    printf("mapping %llu bytes file\n", stbuf.st_size);
  }
  char *mmapped = mmap(NULL, // void *addr,
                       stbuf.st_size , // size_t len, 
                       PROT_READ,      // int prot,
                       MAP_PRIVATE,    //  int flags,
                       fd,             // int fd, 
                       0);             // off_t offset);
  close(fd);
  if (mmapped == MAP_FAILED)  { perror ("mmap"); exit(1);}
  read_entries(mmapped);
/*
  struct entry *ent = alloca (sizeof(struct entry));

  while(pos + 3*sizeof(struct entry) < stbuf.st_size) {

	  ent = (struct entry *) (mmapped + pos );

	  pos += sizeof(struct entry);

	  if ((ent->usually_0x210_or_0x110 != 0x210 && ent->usually_0x210_or_0x110 != 0x110 &&
				  ent->usually_0x210_or_0x110 != 0x310) || 
			  ent->usually_0x00_00)
	  {
		  fprintf (stderr,"Corrupt entry (0x%x at pos %llu).. skipping\n", ent->usually_0x210_or_0x110,pos);
		  int skipping = 1;

		  while (skipping)
		  {
			  ent = (struct entry *) (mmapped + pos ) ;
			  while (ent->usually_0x210_or_0x110 != 0x210 && ent->usually_0x210_or_0x110 != 0x110)
			  {
				  // #@$#$%$# POS ISN'T ALIGNED!
				  pos ++;
				  ent = (struct entry *) (mmapped + pos ) ;
			  }
			  // read rest of entry

			  if (ent->usually_0x00_00 || !nl) {
				  //	 fprintf(stderr,"False positive.. skipping %d\n",pos);
				  pos+=1;


			  }
			  else { skipping =0;
				  pos += sizeof(struct entry); }
		  }

	  }

	  uint32_t	size = swap32(ent->fileSize);

	  // Get Name (immediately after the entry)
	  //
	  // 02/08/2016: Fixed this from alloca() - the Apple jumbo OTAs have so many files in them (THANKS GUYS!!)
	  // that this would exceed the stack limits (could solve with ulimit -s, or also by using
	  // a max buf size and reusing same buf, which would be a lot nicer)


	  // Note to AAPL: Life would have been a lot nicer if the name would have been NULL terminated..
	  // What's another byte per every file in a huge file such as this?
	  // char *name = (char *) (mmapped+pos);

	  char *name = malloc (nameLen+1);

	  strncpy(name, mmapped+pos , nameLen);
	  name[nameLen] = '\0';
	  //printf("NAME IS %s\n", name);

	  pos += ntohs(ent->nameLen);
	  if (g_list){ 
		  if (g_verbose) {
			  printf ("Entry @0x%d: UID: %d GID: %d Size: %d (0x%x) Namelen: %d Name: ", i,
					  size, size,
					  ntohs(ent->nameLen));
		  }
		  printf ("%s\n", name);}

		  // Get size (immediately after the name)
		  uint32_t	fileSize = swap32(ent->fileSize);
		  if (fileSize) 
		  {
			  if (g_extract) { extractFile(mmapped +pos, name, fileSize, g_extract);}
  			pos +=fileSize;
		  }




		  free (name);

  } // Back to loop




  close(fd);
*/
}

