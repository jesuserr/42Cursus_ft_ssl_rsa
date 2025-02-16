/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   base64.h                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jesuserr <jesuserr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/12/15 17:55:08 by jesuserr          #+#    #+#             */
/*   Updated: 2025/02/02 21:38:51 by jesuserr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef BASE64_H
# define BASE64_H

/*
** -.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-
**                              HEADERS
*/
# include "types_encode.h"

/*
** -.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-
**                              DEFINES
*/
# define BASE64_ENC_BLOCKS				3			// 3 * 8 bits (24 bits)
# define BASE64_DEC_BLOCKS				4			// 4 * 6 bits (24 bits)
# define BASE64_LINE					64			// 64 characters per line

/*
** -.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-
**                              STRUCTS
*/
// Base64 table for encoding, the last character is the padding character
static const uint8_t	g_base64_table[65] = \
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

// Reverse table for decoding. Not present values are irrelevant for decoding
// since they are filtered out in the 'proper_encoded_message' function.
static const uint8_t	g_base64_reverse_table[256] = {
['A'] = 0, ['B'] = 1, ['C'] = 2, ['D'] = 3, ['E'] = 4, ['F'] = 5,
['G'] = 6, ['H'] = 7, ['I'] = 8, ['J'] = 9, ['K'] = 10, ['L'] = 11,
['M'] = 12,	['N'] = 13, ['O'] = 14, ['P'] = 15, ['Q'] = 16, ['R'] = 17,
['S'] = 18,	['T'] = 19, ['U'] = 20, ['V'] = 21, ['W'] = 22, ['X'] = 23,
['Y'] = 24,	['Z'] = 25, ['a'] = 26, ['b'] = 27, ['c'] = 28, ['d'] = 29,
['e'] = 30,	['f'] = 31,	['g'] = 32, ['h'] = 33, ['i'] = 34, ['j'] = 35,
['k'] = 36,	['l'] = 37, ['m'] = 38, ['n'] = 39,	['o'] = 40, ['p'] = 41,
['q'] = 42,	['r'] = 43, ['s'] = 44, ['t'] = 45, ['u'] = 46, ['v'] = 47,
['w'] = 48,	['x'] = 49, ['y'] = 50, ['z'] = 51, ['0'] = 52, ['1'] = 53,
['2'] = 54,	['3'] = 55,	['4'] = 56, ['5'] = 57, ['6'] = 58, ['7'] = 59,
['8'] = 60,	['9'] = 61, ['+'] = 62, ['/'] = 63
};

/*
** -.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-
**                        FUNCTION PROTOTYPES
*/
void	base64(t_encode_args *args);
bool	proper_encoded_message(t_encode_args *args);
void	encode_message(t_encode_args *args);

#endif
