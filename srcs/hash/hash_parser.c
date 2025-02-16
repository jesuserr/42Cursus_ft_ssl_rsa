/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   hash_parser.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jesuserr <jesuserr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/11/19 17:12:02 by jesuserr          #+#    #+#             */
/*   Updated: 2025/01/29 10:23:55 by jesuserr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../incs/ft_ssl.h"

static void	parse_options(int opt, t_hash_args *args)
{
	if (opt == 'h')
		print_hash_usage();
	else if (opt == 'p')
		args->echo_stdin = true;
	else if (opt == 'q')
		args->quiet_mode = true;
	else if (opt == 'r')
		args->reverse_output = true;
	else if (opt == 's' && args->print_sum == false)
	{
		args->print_sum = true;
		args->input_str = optarg;
	}
	else if (opt == 's' && args->print_sum == true)
	{
		ft_printf("ft_ssl: %s: %s\n", "-s", "No such file or directory");
		ft_printf("ft_ssl: %s: %s\n", optarg, "No such file or directory");
	}
}

static void	parse_hash_function(t_hash_args *args, char *hash)
{
	if (!ft_strncmp(hash, "md5", 3) && ft_strlen(hash) == 3)
		args->hash_function = 0;
	else if (!ft_strncmp(hash, "sha224", 6) && ft_strlen(hash) == 6)
		args->hash_function = 1;
	else if (!ft_strncmp(hash, "sha256", 6) && ft_strlen(hash) == 6)
		args->hash_function = 2;
	else if (!ft_strncmp(hash, "sha384", 6) && ft_strlen(hash) == 6)
		args->hash_function = 3;
	else if (!ft_strncmp(hash, "sha512", 6) && ft_strlen(hash) == 6)
		args->hash_function = 4;
	else
		print_error_and_exit("Incorrect hash function");
}

// Function deals with both binary and text files. 'isatty' function is used to
// check if the input is coming from a pipe. Message is read in chunks of
// BUFFER_SIZE bytes and with the help of 'realloc' and 'ft_memcpy', the whole
// message is stored in 'input_pipe'. If the file is empty, the program will not
// read anything and the input_pipe will be NULL.
// IMPORTANT: Since input can be binary, the message contained in 'input_pipe' 
// is not null-terminated, and therefore cannot be printed with 'printf'.
static void	parse_pipe(t_hash_args *args)
{
	char		buffer[BUFFER_SIZE];
	char		*temp;
	ssize_t		bytes_read;

	if (isatty(STDIN_FILENO) != 0)
		return ;
	bytes_read = read(STDIN_FILENO, buffer, BUFFER_SIZE);
	while (bytes_read > 0)
	{
		temp = realloc(args->input_pipe, args->pipe_size + (size_t)bytes_read);
		if (!temp)
			print_hash_strerror_and_exit("realloc", args);
		args->input_pipe = temp;
		ft_memcpy(args->input_pipe + args->pipe_size, buffer, \
		(size_t)bytes_read);
		args->pipe_size += (size_t)bytes_read;
		bytes_read = read(STDIN_FILENO, buffer, BUFFER_SIZE);
	}
	if (bytes_read < 0)
	{
		free(args->input_pipe);
		print_error_and_exit("Error reading from pipe");
	}
}

// Uses 'mmap' to map the entire file into memory in one shot. Way more 
// efficient than reading the file multiple times. File size is kept for the
// hash functions to know how many bytes to read (specially for binary files)
// and also for the 'munmap' function to know how many bytes to unmap when the
// program finishes. Empty file case is handled too, otherwise 'mmap' would
// fail.
static void	parse_file_content(t_hash_args *args, char *file_name)
{
	int			fd;
	struct stat	file_stat;
	void		*file_content;

	fd = open(file_name, O_RDONLY);
	if (fd < 0)
		print_hash_strerror_and_exit(file_name, args);
	if (fstat(fd, &file_stat) < 0)
		print_hash_strerror_and_exit(file_name, args);
	if (file_stat.st_size > 0)
	{
		file_content = mmap(NULL, (size_t)file_stat.st_size, PROT_READ, \
		MAP_PRIVATE, fd, 0);
		if (file_content == MAP_FAILED)
		{
			close(fd);
			print_hash_strerror_and_exit("mmap", args);
		}
		args->input_file = (char *)file_content;
	}
	else
		args->input_file = "";
	close(fd);
	args->file_size = (uint64_t)file_stat.st_size;
	args->file_name = file_name;
}

// Parse main function.
void	parse_hash_arguments(int argc, char **argv, t_hash_args *args)
{
	int		opt;

	opt = getopt(argc, argv, "hpqrs:");
	while (opt != -1)
	{
		parse_options(opt, args);
		opt = getopt(argc, argv, "hpqrs:");
	}
	parse_hash_function(args, argv[optind]);
	parse_pipe(args);
	if (!argv[optind + 1] && !args->input_str && !args->input_pipe)
		read_interactive_mode(&args->input_pipe, &args->pipe_size);
	if (optind + 1 < argc)
		parse_file_content(args, argv[optind + 1]);
	if (optind + 2 < argc)
	{
		errno = E2BIG;
		print_hash_strerror_and_exit("hash", args);
	}
}
