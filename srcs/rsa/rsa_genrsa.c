/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   rsa_genrsa.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jesuserr <jesuserr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/02/19 12:15:02 by jesuserr          #+#    #+#             */
/*   Updated: 2025/02/21 20:32:16 by jesuserr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../incs/ft_ssl.h"

// https://en.wikipedia.org/wiki/Modular_exponentiation
// (Right-to-left binary method) Used to avoid overflow when calculating
// (a^d mod n). Allows to compute the result without ever needing to handle the
// potentially huge intermediate values of (a^d).
// 'mod' ('n') never will be 1 since it is filtered out before calling Miller-
// Rabin test. Checked anyways as extra security.
// 'base' ('a') starts with a value of 2 and is incremented in each iteration.
// Therefore will never reach a high value and therefore there is no need to
// protect the multiplications where 'base' is used from overflow.
uint64_t	modular_exponentiation(uint64_t base, uint64_t exp, uint32_t mod)
{
	uint64_t	result;

	if (mod == 1)
		return (0);
	result = 1;
	base = base % mod;
	while (exp > 0)
	{
		if (exp % 2 == 1)
			result = (result * base) % mod;
		exp = exp >> 1;
		base = (base * base) % mod;
	}
	return (result);
}

// https://en.wikipedia.org/wiki/Miller-Rabin_primality_test#Miller-Rabin_test
// Input #1: n > 2, an odd integer to be tested for primality
// Input #2: k, the number of rounds of testing to perform (accuracy)
// Output: "false" if n is found to be composite, otherwise probably prime.
// No need to initialize 'd' since 'n' will be odd and while loop will be run at
// least once. 'a' is initialized to 2 and incremented in each iteration.
// Explore another ways to increase 'a'.
bool	miller_rabin_test(uint32_t n, uint32_t k)
{
	t_miller_rabin_args	args;

	args.s = 1;
	while (((n - 1) % (1U << args.s)) == 0)
		args.d = (n - 1) / (1U << args.s++);
	args.s--;
	args.a = 2;
	while (k--)
	{
		args.x = modular_exponentiation(args.a, args.d, n);
		while (args.s > 0)
		{
			args.y = (args.x * args.x) % n;
			if (args.y == 1 && args.x != 1 && args.x != n - 1)
				return (false);
			args.x = args.y;
			args.s--;
		}
		if (args.y != 1)
			return (false);
		args.a++;
	}
	return (true);
}

// Generate a random 32-bit number reading from /dev/urandom. When cryptographic
// security is needed, reading from /dev/urandom is the most secure way to
// generate random numbers.
// A quick check is done to avoid even numbers and numbers divisible by small
// primes (3, 5, 7 and 11) to eliminate composite numbers without needing the
// full Miller-Rabin test.
uint32_t	generate_random_number(t_rsa_args *args)
{
	int			fd;
	uint32_t	random_number;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
		print_rsa_strerror_and_exit("/dev/urandom", args);
	while (1)
	{
		if (read(fd, &random_number, RSA_KEY_LENGTH / 2) < 0)
			print_rsa_strerror_and_exit("/dev/urandom", args);
		if (random_number % 2 == 0 || random_number % 3 == 0 || \
			random_number % 5 == 0 || random_number % 7 == 0 || \
			random_number % 11 == 0 || random_number <= 1)
			continue ;
		else
			break ;
	}
	close(fd);
	return (random_number);
}

// RSA key generation main function.
void	genrsa(t_rsa_args *args)
{
	while (1)
	{
		args->key.p = generate_random_number(args);
		if (!miller_rabin_test(args->key.p, MR_ITERATIONS))
			continue ;
		args->key.q = generate_random_number(args);
		while (!miller_rabin_test(args->key.q, MR_ITERATIONS))
			args->key.q = generate_random_number(args);
		args->key.n = (uint64_t)args->key.p * (uint64_t)args->key.q;
		if (args->key.n >= 0x8000000000000000)
			break ;
	}
	printf("p: %u\nq: %u\nn: %lu\n", args->key.p, args->key.q, args->key.n);
}

// Parser for genrsa command. Pretty simple since only needs to check for
// output file and help flag. If everything is correct, it calls the genrsa
// function.
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
