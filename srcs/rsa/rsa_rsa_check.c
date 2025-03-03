/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   rsa_rsa_check.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jesuserr <jesuserr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/03/03 13:02:27 by jesuserr          #+#    #+#             */
/*   Updated: 2025/03/03 13:12:30 by jesuserr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../incs/ft_ssl.h"

static void	print_key_error(char *msg, bool *key_ok)
{
	if (*key_ok)
		ft_printf("RSA key not ok\n");
	*key_ok = false;
	ft_printf("Error: %s\n", msg);
}

// Verifies if the private key values are congruent with the RSA algorithm.
void	check_private_key(t_rsa_args *args)
{
	bool	key_ok;

	key_ok = true;
	if (!miller_rabin_test(args->key.p, MR_ITERATIONS, args->verbose))
		print_key_error("prime1 (p) is not prime", &key_ok);
	if (!miller_rabin_test(args->key.q, MR_ITERATIONS, args->verbose))
		print_key_error("prime2 (q) is not prime", &key_ok);
	if (args->key.n != (uint64_t)args->key.p * (uint64_t)args->key.q)
		print_key_error("modulus (n) is not equal to p * q", &key_ok);
	if (args->key.e != 65537)
		print_key_error("publicExponent (e) is not equal to 65537", &key_ok);
	args->key.phi = (uint64_t)(args->key.p - 1) * (uint64_t)(args->key.q - 1);
	if (greatest_common_divisor(args->key.e, args->key.phi) != 1)
		print_key_error("publicExponent (e) and phi are not coprime", &key_ok);
	if (args->key.dmp1 != args->key.d % (args->key.p - 1))
		print_key_error("exponent1 (dmp1) not equal to d % (p - 1)", &key_ok);
	if (args->key.dmq1 != args->key.d % (args->key.q - 1))
		print_key_error("exponent2 (dmq1) not equal to d % (q - 1)", &key_ok);
	if (args->key.iqmp != (uint32_t)modular_multiplicative_inverse(args->key.q, \
	args->key.p))
		print_key_error("coefficient (iqmp) not modular inv of q % p", &key_ok);
	if (key_ok)
		ft_printf("RSA key ok\n");
}
