/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   md5.h                                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jesuserr <jesuserr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/11/21 15:25:42 by jesuserr          #+#    #+#             */
/*   Updated: 2024/12/12 18:24:53 by jesuserr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef MD5_H
# define MD5_H

/*
** -.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-
**                              HEADERS
*/
# include "types_hash.h"

/*
** -.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-
**                              DEFINES
*/
# define MD5_BLOCK			64			// Size in bytes (512 bits)
# define MD5_WORD_SIZE		4			// Size in bytes (32 bits)
# define MD5_OUTPUT_SIZE	16			// Size in bytes (128 bits)

/*
** -.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-
**                              STRUCTS
*/
typedef struct s_md5_data
{
	t_hash_args			*args;			// Passed as a pointer to avoid copying
	uint64_t			msg_len;
	char				*pad_msg;
	uint64_t			pad_len;
	uint32_t			state[4];		// A, B, C, D
	uint32_t			digest[4];		// A, B, C, D
}	t_md5_data;

// Precomputed tables for MD5 Transformations

// Initial values for MD5 buffer digest
static const uint32_t	g_md5_inits[4] = {
	0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};

// Constants derived from the sine function used in each round of the MD5
// transformation process to add a level of complexity and ensure the diffusion
// of the input data.
static const uint32_t	g_md5_sine_add[64] = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,	0xf57c0faf, 0x4787c62a,
	0xa8304613, 0xfd469501,	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
	0x265e5a51, 0xe9b6c7aa,	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,	0xa9e3e905, 0xfcefa3f8,
	0x676f02d9, 0x8d2a4c8a,	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,	0x289b7ec6, 0xeaa127fa,
	0xd4ef3085, 0x04881d05,	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,	0x655b59c3, 0x8f0ccc92,
	0xffeff47d, 0x85845dd1,	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

// Number of left rotations (at bit level) for each round.
static const uint8_t	g_md5_rotations[64] = {
	7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
	5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
	4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
	6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

// Position to read from padded message for each round.
static const uint8_t	g_md5_index[64] = {
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12,
	5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2,
	0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9};

/*
** -.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-
**                        FUNCTION PROTOTYPES
*/
void	md5_sum(t_hash_args *args);

#endif
