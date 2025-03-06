/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   rsa_rsautl_parser.c                                :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jesuserr <jesuserr@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/03/04 13:58:40 by jesuserr          #+#    #+#             */
/*   Updated: 2025/03/06 09:43:41 by jesuserr         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../incs/ft_ssl.h"

// Function copied from encrypt_parser.c. Take comments with a grain of salt.
// Function deals with both binary and text files. 'isatty' function is used to
// check if the input is coming from a pipe. Message is read in chunks of
// BUFFER_SIZE bytes and with the help of 'realloc' and 'ft_memcpy', the whole
// message is stored in 'input_pipe'. If the file is empty, the program will not
// read anything and the input_pipe will be NULL.
// IMPORTANT: Since input can be binary, the message contained in 'input_pipe' 
// is not null-terminated, and therefore cannot be printed with 'printf'.
static void	parse_pipe(t_rsa_args *args)
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
			print_rsa_strerror_and_exit("realloc", args);
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

// Function copied from encrypt_parser.c. Take comments with a grain of salt.
// Uses 'mmap' to map the entire file into memory in one shot. Way more 
// efficient than reading the file multiple times. File size is kept for the
// encrypt functions to know how many bytes to read (specially for binary files)
// and also for the 'munmap' function to know how many bytes to unmap when the
// program finishes. Empty file case is handled too, otherwise 'mmap' would
// fail. Since whitespaces and newlines must be removed from the decoded 
// message (when flag -a is used), mmap is opened as PROT_READ | PROT_WRITE to
// allow this space of memory to be modified.
static void	parse_file_content(t_rsa_args *args, char *file_name)
{
	int			fd;
	struct stat	file_stat;
	void		*file_content;

	fd = open(file_name, O_RDONLY);
	if (fd < 0)
		print_rsa_strerror_and_exit(file_name, args);
	if (fstat(fd, &file_stat) < 0)
		print_rsa_strerror_and_exit(file_name, args);
	if (file_stat.st_size > 0)
	{
		file_content = mmap(NULL, (size_t)file_stat.st_size, \
		PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
		if (file_content == MAP_FAILED)
		{
			close(fd);
			print_rsa_strerror_and_exit("mmap", args);
		}
		args->input_file = (char *)file_content;
	}
	else
		args->input_file = "";
	close(fd);
	args->input_file_size = (uint64_t)file_stat.st_size;
}

// Same as above except for the input key file.
static void	parse_key_content(t_rsa_args *args, char *inkey_file_name)
{
	int			fd;
	struct stat	file_stat;
	void		*file_content;

	fd = open(inkey_file_name, O_RDONLY);
	if (fd < 0)
		print_rsa_strerror_and_exit(inkey_file_name, args);
	if (fstat(fd, &file_stat) < 0)
		print_rsa_strerror_and_exit(inkey_file_name, args);
	if (file_stat.st_size > 0)
	{
		file_content = mmap(NULL, (size_t)file_stat.st_size, \
		PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
		if (file_content == MAP_FAILED)
		{
			close(fd);
			print_rsa_strerror_and_exit("mmap", args);
		}
		args->inkey_content = (char *)file_content;
	}
	else
		args->inkey_content = "";
	close(fd);
	args->inkey_length = (uint64_t)file_stat.st_size;
}

// Parser for rsautl command.
// Input from file has priority over input from pipe.
void	parse_rsautl_arguments(char **argv, t_rsa_args *args)
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
		else if (!ft_strncmp(argv[i], "-in", 3) && ft_strlen(argv[i]) == 3 && \
		argv[i + 1] && argv[i + 1][0] != '-' && !args->input_from_file)
		{
			args->input_from_file = true;
			args->input_file_name = argv[i + 1];
			i++;
		}
		else if (!ft_strncmp(argv[i], "-inkey", 6) && ft_strlen(argv[i]) == 6 \
		&& argv[i + 1] && argv[i + 1][0] != '-' && !args->inkey)
		{
			args->inkey = true;
			args->inkey_file_name = argv[i + 1];
			i++;
		}
		else if (!ft_strncmp(argv[i], "-pubin", 6) && ft_strlen(argv[i]) == 6 \
		&& !args->pub_in)
			args->pub_in = true;
		else if (!ft_strncmp(argv[i], "-encrypt", 8) && ft_strlen(argv[i]) == 8 \
		&& !args->encrypt)
			args->encrypt = true;
		else if (!ft_strncmp(argv[i], "-decrypt", 8) && ft_strlen(argv[i]) == 8 \
		&& !args->decrypt)
			args->decrypt = true;
		else if (!ft_strncmp(argv[i], "-hexdump", 8) && ft_strlen(argv[i]) == 8 \
		&& !args->hexdump)
			args->hexdump = true;
		else if (!ft_strncmp(argv[i], "-crack", 6) && ft_strlen(argv[i]) == 6 \
		&& !args->crack)
			args->crack = true;
		else
			print_error_and_exit("Not recognized option");
		i++;
	}
	if (i == 2 && isatty(STDIN_FILENO) != 0)
		print_error_and_exit("No options provided");
	if (args->decrypt && args->encrypt)
		print_error_and_exit("Cannot use both -encrypt and -decrypt");
	else if (!args->decrypt && !args->encrypt)
		print_error_and_exit("No -encrypt or -decrypt action provided");
	if (!args->inkey)
		print_error_and_exit("No input key provided");
	if (!args->input_from_file)
		parse_pipe(args);
	else
		parse_file_content(args, args->input_file_name);
	if (!args->input_pipe && !args->input_from_file)
		read_interactive_mode(&args->input_pipe, &args->pipe_size);
	if (args->input_file_size > 8 || args->pipe_size > 8)
	{
		errno = EMSGSIZE;
		print_rsa_strerror_and_exit("Message exceeds key length 64 bits", args);
	}
	parse_key_content(args, args->inkey_file_name);
	if (args->output_to_file)
	{
		args->output_fd = open(args->output_file_name, O_CREAT | O_WRONLY | \
		O_TRUNC, 0644);
		if (args->output_fd == -1)
			print_rsa_strerror_and_exit(args->output_file_name, args);
	}
}
