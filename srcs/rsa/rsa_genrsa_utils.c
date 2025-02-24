/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   rsa_genrsa_utils.c                                 :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jesuserr <jesuserr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/02/21 22:46:06 by jesuserr          #+#    #+#             */
/*   Updated: 2025/02/24 14:04:35 by jesuserr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../incs/ft_ssl.h"

// Probability from 0 to 100 is converted to the number of iterations for the
// Miller-Rabin test, where 0 would be 0 and 100 would be MR_ITERATIONS.
static void	test_prime_number(const char *number, const char *p)
{
	uint64_t	nbr;

	if (ft_strlen(p) > 3 || !check_if_only_digits(p) || ft_atoi(p) > 100)
		print_error_and_exit("Probability value must be between 0 and 100");
	if (ft_strlen(number) > 20 || !check_if_only_digits(number) || \
	!string_to_uint64(number, &nbr))
		print_error_and_exit("Number is not a 64 bits unsigned integer");
	if (nbr < 2)
		print_error_and_exit("Number must be greater than 1");
	ft_printf("Prime number tester in progress...\n");
	if (nbr == 2)
	{
		ft_printf("Number 2 is prime\n");
		exit(EXIT_SUCCESS);
	}
	if (miller_rabin_test(nbr, (ft_atoi(p) * MR_ITERATIONS) / 100, false))
		ft_printf("Number %s is probably prime at %s%%\n", number, p);
	else
		ft_printf("Number %s is not prime\n", number);
	exit(EXIT_SUCCESS);
}

// Parser for genrsa command. Checks for output file, help and verbose flags.
// Also checks for -test flag to test if a number is prime.
void	parse_genrsa_arguments(char **argv, t_rsa_args *args)
{
	int	i;

	args->output_fd = STDOUT_FILENO;
	i = 2;
	while (argv[i])
	{
		if (!ft_strncmp(argv[i], "-h", 2) && ft_strlen(argv[i]) == 2)
			print_rsa_usage();
		else if (!ft_strncmp(argv[i], "-out", 4) && ft_strlen(argv[i]) == 4 && \
		argv[i + 1] && argv[i + 1][0] != '-' && !args->output_to_file)
		{
			args->output_to_file = true;
			args->output_file_name = argv[i + 1];
			i++;
		}
		else if (!ft_strncmp(argv[i], "-test", 5) && ft_strlen(argv[i]) == 5 && \
		argv[i + 1] && argv[i + 1][0] != '-' && argv[i + 2] && \
		argv[i + 2][0] != '-')
			test_prime_number(argv[i + 1], argv[i + 2]);
		else if (!ft_strncmp(argv[i], "-verbose", 8) && ft_strlen(argv[i]) == 8 \
		&& !args->verbose)
			args->verbose = true;
		else
			print_error_and_exit("Not recognized option");
		i++;
	}
	if (args->output_to_file)
	{
		args->output_fd = open(args->output_file_name, O_CREAT | O_WRONLY | \
		O_TRUNC, 0644);
		if (args->output_fd == -1)
			print_rsa_strerror_and_exit(args->output_file_name, args);
	}
	genrsa(args);
}

// Modifies the endianess of the RSA key values to be stored in the private key
void	modify_key_values_endianness(t_rsa_key *key)
{
	modify_endianness_64_bits(&key->n);
	modify_endianness_64_bits(&key->d);
	modify_endianness_32_bits(&key->p);
	modify_endianness_32_bits(&key->q);
	modify_endianness_32_bits(&key->dmp1);
	modify_endianness_32_bits(&key->dmq1);
	modify_endianness_32_bits(&key->iqmp);
}
