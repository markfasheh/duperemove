/*
 * kernel.h
 *
 * This code taken from the linux kernel, and is Copyright (C) 2016
 * the original contributers.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */

#ifndef _LINUX_KERNEL_H
#define _LINUX_KERNEL_H

#include <inttypes.h>

#define	u8	uint8_t

/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:	the pointer to the member.
 * @type:	the type of the container struct this is embedded in.
 * @member:	the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})

#define	WRITE_ONCE(dest, src)	(dest) = (src)
#define	READ_ONCE(a)	(a)

#endif
