/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   types_rsa.h                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jesuserr <jesuserr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/02/17 19:20:59 by jesuserr          #+#    #+#             */
/*   Updated: 2025/02/21 20:04:55 by jesuserr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef TYPES_RSA_H
# define TYPES_RSA_H

/*
** -.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-
**                              DEFINES
*/
# define RSA_KEY_LENGTH			8U			// Key length in bytes (64 bits)
# define MR_ITERATIONS			30U			// Iterations for Miller-Rabin test

/*
** -.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-
**                              STRUCTS
*/
typedef struct s_rsa_key
{
	uint32_t	p;
	uint32_t	q;
	uint64_t	n;
}	t_rsa_key;

typedef struct s_rsa_args
{
	char		*output_file_name;
	int			output_fd;
	bool		output_to_file;
	uint8_t		rsa_function;
	t_rsa_key	key;
}	t_rsa_args;

typedef struct s_miller_rabin_args
{
	uint64_t	s;
	uint64_t	d;
	uint64_t	a;
	uint64_t	x;
	uint64_t	y;
}	t_miller_rabin_args;

enum	e_rsa_functions
{
	GENRSA,
	RSA,
	RSAUTL
};

#endif
