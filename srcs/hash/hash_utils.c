/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   hash_utils.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jesuserr <jesuserr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/12/12 19:47:43 by jesuserr          #+#    #+#             */
/*   Updated: 2025/02/04 12:25:20 by jesuserr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../incs/ft_ssl.h"

// Uses an array of function pointers to call the hashing function selected by
// the user. Performs up to three calls to the hashing function, one for each
// possible input source (pipe, string or file) that has some content.
void	calls_to_hashing_function(t_hash_args *args)
{
	void		(*hash_functions[])(t_hash_args *) = \
				{md5_sum, sha224_sum, sha256_sum, sha384_sum, sha512_sum};
	char		*msg[3];
	uint8_t		origin;

	msg[IS_PIPE] = args->input_pipe;
	msg[IS_STRING] = args->input_str;
	msg[IS_FILE] = args->input_file;
	origin = IS_PIPE;
	while (origin <= IS_FILE)
	{
		if (msg[origin])
		{
			args->msg_origin = origin;
			args->message = msg[origin];
			hash_functions[args->hash_function](args);
		}
		origin++;
	}
	if (args->input_pipe)
		free(args->input_pipe);
	if (args->input_file && args->file_size > 0)
		if (munmap(args->input_file, args->file_size) < 0)
			print_hash_strerror_and_exit("munmap", args);
}

void	print_hash_usage(void)
{
	ft_printf("Usage\n"
		"  ./ft_ssl <command> [flags] [file]\n\n"
		"Hash options:\n"
		"  command     md5, sha224, sha256, sha384 or sha512\n"
		"  -h          print help and exit\n"
		"  -p          echo STDIN to STDOUT and append the checksum to STDOUT\n"
		"  -q          quiet mode\n"
		"  -r          reverse the format of the output\n"
		"  -s <string> print the sum of the given string\n");
	exit(EXIT_SUCCESS);
}

// Prints system error message, releases allocated memory and exits with 
// EXIT_FAILURE status.
void	print_hash_strerror_and_exit(char *msg, t_hash_args *args)
{
	ft_putstr_fd(msg, STDERR_FILENO);
	ft_putstr_fd(": ", STDERR_FILENO);
	ft_putstr_fd(strerror(errno), STDERR_FILENO);
	ft_putstr_fd("\n", STDERR_FILENO);
	if (args->input_pipe)
		free(args->input_pipe);
	if (args->input_file)
		munmap(args->input_file, args->file_size);
	exit(EXIT_FAILURE);
}

// Auxilary function for print_xxx_digest that is common to all hash functions.
// Since message from pipe can be not null-terminated, it is managed separately.
void	print_prehash_output(char *algorithm, t_hash_args *args)
{
	if (args->msg_origin == IS_PIPE && !args->echo_stdin)
		ft_printf("(stdin)= ");
	else if (args->msg_origin == IS_PIPE && args->echo_stdin)
		print_message_from_pipe(args);
	else if (args->msg_origin == IS_STRING && !args->reverse_output)
		ft_printf("%s (\"%s\") = ", algorithm, args->message);
	else if (args->msg_origin == IS_FILE && !args->reverse_output)
		ft_printf("%s (%s) = ", algorithm, args->file_name);
}

// Since message coming from stdin can be not null-terminated, write() is used 
// instead of printf() to print the exact length of the message. Function
// removes also the newline character from the end of the message if it has been
// introduced by the 'echo' command when reading from stdin (pipe). Modified 
// only for printing purposes, for hashing purposes the message with the newline
// character is processed.
void	print_message_from_pipe(t_hash_args *args)
{
	if (args->pipe_size > 0 && args->message[args->pipe_size - 1] == '\n')
		args->message[args->pipe_size - 1] = '\0';
	if (args->quiet_mode)
	{
		write (STDOUT_FILENO, args->message, args->pipe_size);
		ft_printf("\n");
	}
	else
	{
		ft_printf("(\"");
		write (STDOUT_FILENO, args->message, args->pipe_size);
		ft_printf("\")= ");
	}
}
