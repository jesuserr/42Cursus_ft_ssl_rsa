/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   encode_utils.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jesuserr <jesuserr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/12/15 13:12:56 by jesuserr          #+#    #+#             */
/*   Updated: 2025/02/04 12:25:26 by jesuserr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../incs/ft_ssl.h"

// At the contrary of the hashing functions, the encoding function is just 
// called once, since the input can only come from one source.
void	calls_to_decoding_function(t_encode_args *args)
{
	if (args->input_pipe)
	{
		args->message = args->input_pipe;
		args->message_length = args->pipe_size;
		base64(args);
		free(args->input_pipe);
	}
	if (args->input_file)
	{
		args->message = args->input_file;
		args->message_length = args->input_file_size;
		base64(args);
		if (args->input_file_size > 0)
			if (munmap(args->input_file, args->input_file_size) < 0)
				print_encode_strerror_and_exit("munmap", args);
	}
	if (args->output_to_file && args->output_fd != STDOUT_FILENO)
		if (close(args->output_fd) < 0)
			print_encode_strerror_and_exit("close", args);
}

void	print_encode_usage(void)
{
	ft_printf("Usage\n"
		"  ./ft_ssl <command> [flags] [file]\n\n"
		"Encode options:\n"
		"  command     base64\n"
		"  -h          print help and exit\n"
		"  -d          decode mode\n"
		"  -e          encode mode (default)\n"
		"  -i <file>   input file\n"
		"  -o <file>   output file\n");
	exit(EXIT_SUCCESS);
}

// Prints system error message, releases allocated memory and file descriptor
// and exits with EXIT_FAILURE status.
void	print_encode_strerror_and_exit(char *msg, t_encode_args *args)
{
	ft_putstr_fd(msg, STDERR_FILENO);
	ft_putstr_fd(": ", STDERR_FILENO);
	ft_putstr_fd(strerror(errno), STDERR_FILENO);
	ft_putstr_fd("\n", STDERR_FILENO);
	if (args->input_pipe)
		free(args->input_pipe);
	if (args->input_file)
		munmap(args->input_file, args->input_file_size);
	if (args->output_to_file && args->output_fd != STDOUT_FILENO)
		close(args->output_fd);
	exit(EXIT_FAILURE);
}

// Removes whitespaces and newlines from the message for proper decoding.
void	remove_message_whitespaces_and_newlines(t_encode_args *args)
{
	uint64_t	i;
	uint64_t	j;

	i = 0;
	j = 0;
	while (i < args->message_length)
	{
		if (args->message[i] != ' ' && args->message[i] != '\n')
		{
			args->message[j] = args->message[i];
			j++;
		}
		i++;
	}
	args->message_length = j;
}
