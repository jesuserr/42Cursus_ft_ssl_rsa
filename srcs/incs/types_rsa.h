/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   types_rsa.h                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jesuserr <jesuserr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/02/17 19:20:59 by jesuserr          #+#    #+#             */
/*   Updated: 2025/02/20 11:01:30 by jesuserr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef TYPES_RSA_H
# define TYPES_RSA_H

/*
** -.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-
**                              DEFINES
*/
# define RSA_KEY_LENGTH			8U			// Key length in bytes (64 bits)

/*
** -.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-.-'-
**                              STRUCTS
*/
typedef struct s_rsa_args
{
	char		*output_file_name;
	int			output_fd;
	bool		output_to_file;
	uint8_t		rsa_function;
}	t_rsa_args;

enum	e_rsa_functions
{
	GENRSA,
	RSA,
	RSAUTL
};

#endif
