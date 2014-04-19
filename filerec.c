#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "list.h"

#include "filerec.h"

struct list_head filerec_list;

struct filerec *filerec_new(const char *filename)
{
	struct filerec *file = calloc(1, sizeof(*file));

	if (file) {
		file->filename = strdup(filename);
		if (!file->filename) {
			free(file);
			return NULL;
		}

		file->fd = -1;
		INIT_LIST_HEAD(&file->block_list);
		INIT_LIST_HEAD(&file->extent_list);
		INIT_LIST_HEAD(&file->tmp_list);

		list_add_tail(&file->rec_list, &filerec_list);
	}
	return file;
}

void filerec_free(struct filerec *file)
{
	if (file) {
		filerec_close(file);

		free(file->filename);

		list_del(&file->block_list);
		list_del(&file->extent_list);
		list_del(&file->rec_list);
		list_del(&file->tmp_list);

		free(file);
	}
}

int filerec_open(struct filerec *file, int write)
{
	int fd, flags = O_RDONLY;

	if (write)
		flags = O_RDWR;

	if (file->fd == -1) {
		fd = open(file->filename, flags);
		if (fd == -1) {
			fprintf(stderr, "Error %d: %s while opening \"%s\" "
				"(write=%d)\n",
				errno, strerror(errno), file->filename, write);
			return errno;
		}

		file->fd = fd;
	}

	return 0;
}

void filerec_close(struct filerec *file)
{
	if (file->fd != -1) {
		close(file->fd);
		file->fd = -1;
	}
}
