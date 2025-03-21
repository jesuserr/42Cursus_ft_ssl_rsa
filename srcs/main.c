/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jesuserr <jesuserr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/11/19 17:12:21 by jesuserr          #+#    #+#             */
/*   Updated: 2025/03/04 13:57:35 by jesuserr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "incs/ft_ssl.h"

static uint8_t	pre_parser(int argc, char **argv)
{
	if (argc < 2)
		print_error_and_exit("Hash/Cypher/RSA function required");
	if ((!ft_strncmp(argv[1], "md5", 3) && ft_strlen(argv[1]) == 3) || \
		(!ft_strncmp(argv[1], "sha224", 6) && ft_strlen(argv[1]) == 6) || \
		(!ft_strncmp(argv[1], "sha256", 6) && ft_strlen(argv[1]) == 6) || \
		(!ft_strncmp(argv[1], "sha384", 6) && ft_strlen(argv[1]) == 6) || \
		(!ft_strncmp(argv[1], "sha512", 6) && ft_strlen(argv[1]) == 6))
		return (HASH_COMMAND);
	else if (!ft_strncmp(argv[1], "base64", 6) && ft_strlen(argv[1]) == 6)
		return (ENCODE_COMMAND);
	else if ((!ft_strncmp(argv[1], "des", 3) && ft_strlen(argv[1]) == 3) || \
		(!ft_strncmp(argv[1], "des-ecb", 7) && ft_strlen(argv[1]) == 7) || \
		(!ft_strncmp(argv[1], "des-cfb", 7) && ft_strlen(argv[1]) == 7) || \
		(!ft_strncmp(argv[1], "des-ofb", 7) && ft_strlen(argv[1]) == 7) || \
		(!ft_strncmp(argv[1], "des-cbc", 7) && ft_strlen(argv[1]) == 7))
		return (ENCRYPT_COMMAND);
	else if ((!ft_strncmp(argv[1], "genrsa", 6) && ft_strlen(argv[1]) == 6) || \
		(!ft_strncmp(argv[1], "rsa", 3) && ft_strlen(argv[1]) == 3) || \
		(!ft_strncmp(argv[1], "rsautl", 6) && ft_strlen(argv[1]) == 6))
		return (RSA_COMMAND);
	else if (!ft_strncmp(argv[1], "-h", 2) && ft_strlen(argv[1]) == 2)
		print_total_usage();
	return (0);
}

static void	init_structs(t_hash_args *hash_args, t_encode_args *encode_args, \
			t_encrypt_args *encrypt_args, t_rsa_args *rsa_args)
{
	ft_bzero(hash_args, sizeof(t_hash_args));
	ft_bzero(encode_args, sizeof(t_encode_args));
	ft_bzero(encrypt_args, sizeof(t_encrypt_args));
	ft_bzero(rsa_args, sizeof(t_rsa_args));
}

int	main(int argc, char **argv)
{
	t_hash_args		hash_args;
	t_encode_args	encode_args;
	t_encrypt_args	encrypt_args;
	t_rsa_args		rsa_args;

	init_structs(&hash_args, &encode_args, &encrypt_args, &rsa_args);
	if (pre_parser(argc, argv) == HASH_COMMAND)
	{
		parse_hash_arguments(argc, argv, &hash_args);
		calls_to_hashing_function(&hash_args);
	}
	else if (pre_parser(argc, argv) == ENCODE_COMMAND)
	{
		parse_encode_arguments(argc, argv, &encode_args);
		calls_to_decoding_function(&encode_args);
	}
	else if (pre_parser(argc, argv) == ENCRYPT_COMMAND)
	{
		parse_encrypt_arguments(argc, argv, &encrypt_args);
		calls_to_encrypt_function(&encrypt_args);
	}
	else if (pre_parser(argc, argv) == RSA_COMMAND)
		choose_rsa_function(argv, &rsa_args);
	else
		print_error_and_exit("Wrong Hash/Cipher/RSA command");
	return (EXIT_SUCCESS);
}
