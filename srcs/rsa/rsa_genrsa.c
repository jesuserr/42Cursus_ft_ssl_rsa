/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   genrsa.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jesuserr <jesuserr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/02/19 12:15:02 by jesuserr          #+#    #+#             */
/*   Updated: 2025/02/19 23:09:05 by jesuserr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../incs/ft_ssl.h"

bool is_prime(uint64_t n)
{
	if (n <= 1)
		return false;
	if (n <= 3)
		return true;
	if (n % 2 == 0 || n % 3 == 0)
		return false;
	for (uint64_t i = 5; i * i <= n; i += 6)
		if (n % i == 0 || n % (i + 2) == 0)
			return false;
	return true;
}

// RSA key generation main function.
void	genrsa(t_rsa_args *args)
{
	(void)args;
	ft_printf("genrsa\n");
	int			fd;
	uint32_t	random_number;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
		print_rsa_strerror_and_exit("/dev/urandom", args);
	int j = 0;
	for (int i = 0; i < 10; i++)
	{
		if (read(fd, &random_number, RSA_KEY_LENGTH / 2) < 0)
			print_rsa_strerror_and_exit("/dev/urandom", args);
		if (random_number % 2 == 0 || random_number % 3 == 0 || \
			random_number % 5 == 0 || random_number % 7 == 0)
			i--;
		else
		{
			printf("Random number: %u\t", random_number);
			printf("is prime: %d\n", is_prime(random_number));
		}
		j++;
	}
	printf("Total random numbers: %d\n", j);
	close(fd);	
}

// Parser for genrsa command. Pretty simple since only needs to check for
// output file and help flag. If everything is correct, it calls the genrsa
// function.
void	parse_genrsa_arguments(int argc, char **argv, t_rsa_args *args)
{
	int		opt;

	args->output_fd = STDOUT_FILENO;
	opt = getopt(argc, argv, "ho:");
	while (opt != -1)
	{
		if (opt == 'h')
			print_rsa_usage();
		else if (opt == 'o' && !args->output_to_file)
		{
			args->output_to_file = true;
			args->output_fd = open(optarg, O_CREAT | O_WRONLY | O_TRUNC, 0644);
			if (args->output_fd == -1)
				print_rsa_strerror_and_exit(optarg, args);
		}
		opt = getopt(argc, argv, "ho:");
	}
	if (++optind < argc)
	{
		errno = EINVAL;
		print_rsa_strerror_and_exit("Not recognized option", args);
	}
	genrsa(args);
}
