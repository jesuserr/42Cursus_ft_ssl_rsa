/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   rsa_utils.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jesuserr <jesuserr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/02/19 11:59:02 by jesuserr          #+#    #+#             */
/*   Updated: 2025/03/05 11:56:45 by jesuserr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../incs/ft_ssl.h"

// At the contrary of the hashing functions, the encrypt function is just 
// called once, since the input can only come from one source. File has
// priority over pipe, so if both are provided, the pipe will be ignored.
void	calls_to_rsa_functions(t_rsa_args *args)
{
	void	(*rsa_functions[])(t_rsa_args *) = {genrsa, rsa};

	if (args->rsa_function == GENRSA)
		rsa_functions[args->rsa_function](args);
	if (args->input_pipe)
	{
		args->message = args->input_pipe;
		args->message_length = args->pipe_size;
		rsa_functions[args->rsa_function](args);
		free(args->input_pipe);
	}
	if (args->input_file)
	{
		args->message = args->input_file;
		args->message_length = args->input_file_size;
		rsa_functions[args->rsa_function](args);
		if (args->input_file_size > 0)
			if (munmap(args->input_file, args->input_file_size) < 0)
				print_rsa_strerror_and_exit("munmap", args);
	}
	if (args->output_to_file && args->output_fd != STDOUT_FILENO)
		if (close(args->output_fd) < 0)
			print_rsa_strerror_and_exit("close", args);
	if (args->inkey_content)
		if (munmap(args->inkey_content, args->inkey_length) < 0)
			print_rsa_strerror_and_exit("munmap", args);
}

void	print_rsa_usage(void)
{
	ft_printf("Usage\n"
		"  ./ft_ssl <command> [flags] [file]\n\n"
		"RSA options:\n  command         genrsa, rsa, rsautl\n"
		"  -h              print help and exit\n"
		"  -inform PEM     input format is PEM (default)\n"
		"  -outform PEM    output format is PEM (default)\n"
		"  -in <file>      input file\n"
		"  -passin arg     input file password source\n"
		"  -out <file>     output file\n"
		"  -passout arg    output file password source\n"
		"  -des            encrypt the output with DES in CBC mode\n"
		"  -text           print the key in plain text\n"
		"  -noout          do not output encoded version of key\n"
		"  -modulus        print value of key modulus\n"
		"  -check          verify key consistency\n"
		"  -pubin          read public key from input file\n"
		"  -pubout         print public key\n"
		"  -inkey <file>   input key (RSA private key by default)\n"
		"  -encrypt        encrypt input data with public key\n"
		"  -decrypt        decrypt input data with private key\n"
		"  -hexdump        print the key in hexadecimal\n"
		"  -verbose        print details during key generation\n"
		"  -test <n> <p>   test if n is prime at p probability\n");
	exit(EXIT_SUCCESS);
}

// Prints system error message, releases allocated memory and file descriptor
// and exits with EXIT_FAILURE status.
void	print_rsa_strerror_and_exit(char *msg, t_rsa_args *args)
{
	ft_putstr_fd(msg, STDERR_FILENO);
	ft_putstr_fd(": ", STDERR_FILENO);
	ft_putstr_fd(strerror(errno), STDERR_FILENO);
	ft_putstr_fd("\n", STDERR_FILENO);
	if (args->output_to_file && args->output_fd != STDOUT_FILENO)
		close(args->output_fd);
	if (args->input_pipe)
		free(args->input_pipe);
	if (args->input_file)
		munmap(args->input_file, args->input_file_size);
	if (args->inkey_content)
		munmap(args->inkey_content, args->inkey_length);
	exit(EXIT_FAILURE);
}

void	choose_rsa_function(char **argv, t_rsa_args *args)
{
	if (!ft_strncmp(argv[1], "genrsa", 6) && ft_strlen(argv[1]) == 6)
	{
		args->rsa_function = GENRSA;
		parse_genrsa_arguments(argv, args);
		calls_to_rsa_functions(args);
	}
	else if (!ft_strncmp(argv[1], "rsa", 3) && ft_strlen(argv[1]) == 3)
	{
		args->rsa_function = RSA;
		parse_rsa_arguments(argv, args);
		calls_to_rsa_functions(args);
	}
	else if (!ft_strncmp(argv[1], "rsautl", 6) && ft_strlen(argv[1]) == 6)
	{
		args->rsa_function = RSAUTL;
		parse_rsautl_arguments(argv, args);
	}
}
