#include <stdio.h>
#include <dirent.h>
#include <fcntl.h>
#include <readline/history.h>
#include <readline/readline.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>
#include <errno.h>
// value of text color\033[37;3m aftert =
// #define PROMPT_MSG "\033[36;6mminishell\33[0m:"
#define PROMPT_MSG "minishell-3.2$ "

#define ARGS_TYPE 0
#define REDIR_TYPE 1
#define CONDITION_TYPE 2
#define PARENT_TYPE 3
#define ERROR_TYPE 4
#define VALID_LLONG 9
#define I_REDIR 0
#define O_REDIR 1
#define APPEN 2
#define HERED 3
#define REDIR_ERR -1
#define PIPE 1
#define OP_OR 2
#define OP_AND 3

typedef struct s_map_list
{
	char *key;
	char *value;
	struct s_map_list *next;
} t_map_list;

typedef struct s_control_sig
{
	struct sigaction sa_int;
	struct sigaction sa_quit;
} t_control_sig;

typedef struct s_list
{
	char *s; // cmd[0] == name
	struct s_list *next;
} t_list;

typedef struct s_redirect
{
	int type;
	char *front_fd;
	char *back_fd;
	char *heredoc;
	struct s_redirect *next;
} t_redirect;

typedef struct s_exec
{
	int run_condition;
	t_list *cmd;
	t_redirect *redir;
	struct s_exec *child;
	struct s_exec *next;
} t_exec;

void install_term()
{
	struct termios term;
	tcgetattr(STDIN_FILENO, &term);
	term.c_lflag &= ~ECHOCTL;
	tcsetattr(STDIN_FILENO, TCSANOW, &term);
}

typedef struct s_tok_list
{
	int token;
	char *str;
	struct s_tok_list *next;
	struct s_tok_list *child;
} t_tok_list;

typedef struct
{
	int read_fd;
	int write_fd;
} t_pipe;

volatile int sigint_in;

void sig_handler(int signal)
{
	if (signal == SIGINT)
	{
		printf("\n");
		rl_replace_line("", 0);
		rl_on_new_line();
		rl_redisplay();
	}
	else if (signal == SIGQUIT)
		return;
}

void ft_rl_new(int sig)
{
	if (sig == SIGINT)
	{
		printf("\n");
		rl_replace_line("", 0);
		rl_on_new_line();
	}
}

void child_ignore(void)
{
	struct sigaction sa;

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = &ft_rl_new;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);
}

void sig_ignore()
{
	struct sigaction sa;

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = SIG_IGN;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);
}

void sig_hered(int signal)
{
	install_term();
	if (signal == SIGINT)
	{
		printf("\n");
		exit(1);
	}
	else if (signal == SIGQUIT)
		return;
}

void mod_sig_handle(void (*fn)(int))
{
	struct sigaction sa;

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = fn;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);
}

void intstall_term()
{
	struct termios term;
	tcgetattr(STDIN_FILENO, &term);
	term.c_lflag &= ~ECHOCTL;
	tcsetattr(STDIN_FILENO, TCSANOW, &term);
}

void sigint_handler(int signum, siginfo_t *info, void *ptr)
{
	t_pipe *pipe_fds = (t_pipe *)info->si_value.sival_ptr;
	if (signum == SIGINT)
	{
		printf("\n");
		sigint_in = 1;
		close(pipe_fds->write_fd);
		// exit(EXIT_FAILURE);
	}
}

void sig_setup_heredoc()
{
	struct sigaction sa;

	sa.sa_sigaction = sigint_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_SIGINFO;
	sa.sa_flags |= SA_RESTART;
	sigaction(SIGINT, &sa, NULL);
	signal(SIGQUIT, SIG_IGN);
}
// ft_split
static size_t num_genr(char const *s, char c, int indc, int line)
{
	size_t count;
	size_t i;
	size_t target;

	target = 0;
	count = 0;
	i = -1;
	while (s[++i])
	{
		if (i != 0 && s[i - 1] != c && s[i] == c)
			count++;
		else if (s[i] != c && s[i + 1] == 0)
			count++;
		if ((int)count == line && indc == 0)
			return (target);
		else if (indc == 1 && s[i] != c && s[i + 1] == 0)
			return (i + 1);
		else if ((int)count == line && indc == 1)
			return (i);
		if (s[i] == c)
			target = i + 1;
	}
	return (count);
}

static char *cup_noodle_malloc(const char *src, char c, size_t line)
{
	size_t start;
	size_t end;
	size_t i;
	char *dst;

	i = 0;
	start = num_genr(src, c, 0, line);
	end = num_genr(src, c, 1, line);
	dst = (char *)malloc((end - start) + 1);
	if (!dst)
		return (0);
	while (start != end)
		dst[i++] = *(src + (start++));
	dst[i] = 0;
	return (dst);
}

static int free_time(char **s, char const *root, char c, size_t line)
{
	size_t end_line;

	end_line = num_genr(root, c, -1, -1);
	while (line <= end_line && line++ != 0)
		free(s[line - 2]);
	free(s);
	return (1);
}

char **ft_split(char const *s, char c)
{
	size_t line;
	char **ptr_result;

	if (!s)
		return (0);
	line = num_genr(s, c, -1, -1);
	ptr_result = malloc(sizeof(char *) * (line + 1));
	if (!ptr_result)
		return (0);
	if (!line)
	{
		ptr_result[0] = 0;
		return (ptr_result);
	}
	ptr_result[line] = 0;
	while (line-- != 0)
	{
		ptr_result[line] = cup_noodle_malloc(s, c, (line + 1));
		if (!ptr_result[line] && free_time(ptr_result, s, c, line))
			return (0);
	}
	return (ptr_result);
}

//--------------------------------->

// for replace $ -------------------------
void replace_str(char **str, t_map_list *env, int status);
void unquote_realloc_str(char **str);

// ---------------------------------------

void ft_add_maplist(t_map_list **head, char **src)
{
	t_map_list *new;
	t_map_list *temp;

	new = malloc(sizeof(t_map_list));
	new->key = strdup(src[0]);
	if (src[1])
		new->value = strdup(src[1]);
	new->next = NULL;
	if (*head == NULL)
		*head = new;
	else
	{
		temp = *head;
		while (temp->next)
			temp = temp->next;
		temp->next = new;
	}
}

void ft_free_chrarr(char **arr);

t_map_list *get_env_list(char **env)
{
	size_t i;
	char **temp;
	t_map_list *head;

	head = NULL;
	i = 0;
	while (env[i])
	{
		temp = ft_split(env[i], '=');
		ft_add_maplist(&head, temp);
		ft_free_chrarr(temp);
		free(temp);
		i++;
	}
	temp = NULL;
	return (head);
}


t_map_list *ft_new_mapnode(char *key, char *value)
{
	t_map_list *new_node = (t_map_list *)malloc(sizeof(t_map_list));
	if (new_node != NULL)
	{
		new_node->key = strdup(key);
		if (value == 0)
			new_node->value = calloc(1, 1);
		else
			new_node->value = strdup(value);
		new_node->next = NULL;
	}
	return new_node;
}

// ---------------- end env ------------ part

// ---------------- struct input ------- part

// ---------------- get_ stuff --------- part


// ---------------- make string -----------

int ft_is_space(int c)
{
	if ((c >= '\t' && c <= '\r') || c == ' ')
		return (1);
	return (0);
}

void manage_string_helper(int *token, int *quote_indicate, int chr)
{
	if (*quote_indicate == 0)
	{
		*quote_indicate = 1;
		*token = chr;
	}
	else if (*quote_indicate == 1 && *token == chr)
	{
		*quote_indicate = 0;
		*token = 0;
	}
}

int	manage_string_space_return (int quote)
{
	if (quote != 0)
	{
		write(2, "minishell : syntax error near unexpected token `", 48);
		write(2, "newline`\n", 9);
		return (1);
	}
	return (0);
}

char *manage_string_space(char *src)
{
	int i;
	int quote;
	char *res;
	int token;

	i = 0;
	quote = 0;
	res = (char *)calloc(strlen(src) + 1, 1);
	while (src[i])
	{
		if (strchr("\'\"", src[i]))
			manage_string_helper(&token, &quote, src[i]);
		if (ft_is_space(src[i]) && quote == 0)
			res[i] = ' ';
		else
			res[i] = src[i];
		i++;
	}
	free(src);
	src = NULL;
	if (manage_string_space_return(quote))
		return (NULL);
	return (res);
}

// ----------- group token list ------

t_tok_list *ft_new_toklist(void)
{
	t_tok_list *new;

	new = malloc(sizeof(t_tok_list));
	new->token = ARGS_TYPE;
	new->str = NULL;
	new->next = NULL;
	new->child = NULL;
	return (new);
}

int ft_strnum(char *s)
{
	while ((*s >= '0' && *s <= '9') || *s == '&')
		s++;
	if (*s == 0)
		return (1);
	return (0);
}

// ------------------ helper function ------------
int valid_quote(char *str)
{
	int token;
	char *temp;

	temp = str;
	token = *str;
	str++;
	while (*str && *str != token)
		str++;
	if (*str == token)
		return (str - temp);
	return (0);
}

void recursive_token_quote_helper(char **src, char **ptr, int *type)
{
	int token;

	token = **src;
	**ptr = **src;
	*src += 1;
	*ptr += 1;
	while (**src && **src != token)
	{
		**ptr = **src;
		*ptr += 1;
		*src += 1;
	}
	**ptr = **src;
	*ptr += 1;
}

void	recursive_token_redir_add_char(char **src, int chr_buf, char **buf_ptr, int *count)
{
	while (**src == chr_buf)
	{
		**buf_ptr = **src;
		*buf_ptr += 1;
		*src += 1;
		count++;
	}
}

void recursive_token_redir_helper(char **src, char **buf_ptr, int *token)
{
	int count;
	int chr_buf;

	count = 0;
	*token = REDIR_TYPE;
	chr_buf = **src;
	recursive_token_redir_add_char(src, chr_buf, buf_ptr, &count);
	if (count > 2)
		*token = ERROR_TYPE;
	if (**src == '&')
	{
		if (*(*src + 1) && *(*src + 1) == '&')
		{
			src--;
			return;
		}
	}
	while (**src && strchr("|<>()\'\" ", **src) == NULL &&
		   ft_is_space(**src) == 0)
	{
		**buf_ptr = **src;
		*buf_ptr += 1;
		*src += 1;
	}
}

void recursive_token_cond_helper(char **src, char **ptr, int *token)
{
	int buf_token;
	char *temp;

	buf_token = **src;
	*token = CONDITION_TYPE;
	if (**src == '&' && *(*src + 1) && *(*src + 1) != '&')
	{
		**ptr = **src;
		*ptr += 1;
		*token = ARGS_TYPE;
		return;
	}
	while (**src && **src == buf_token)
	{
		**ptr = **src;
		*ptr += 1;
		*src += 1;
	}
}

int	check_paren_valid_error(char *str)
{
	write(2, "minishell : syntax error unexpected token at ", 45);
	write(2, "`", 1);
	if (strchr(str, ')'))
		write(2, ")", 1);
	else
		write(2, "newline", 7);
	write(2, "`\n", 2);
	return (0);
}

void	check_paren_valid_in_quote(char **src_str, int *token)
{
	*token = src_str[0][0];
	src_str[0] += 1;
	while (src_str[0] && src_str[0][0] != *token)
		src_str[0] += 1;
	if (src_str[0][0] == 0)
		src_str[0] -= 1;
}
int check_paren_valid(char *str)
{
	int count;
	int token;
	int quote_count;

	count = 0;
	while (*str)
	{
		if (*str == '(')
			count++;
		else if (*str == ')')
			count--;
		else if (strchr("\'\"", *str))
			check_paren_valid_in_quote(&str, &token);
		if (count < 0)
			break;
		str++;
	}
	if (count == 0)
		return (1);
	return (check_paren_valid_error(str));
}

void recursive_token(char *src, t_tok_list **branch, int root_call, char *temp);

void recursive_token_paren_helper(char **src, int *token, t_tok_list **list)
{
	char *buf;
	char *buf_ptr;
	int count;
	char *temp;

	// *list = ft_new_toklist();
	*token = PARENT_TYPE;
	count = 1;
	*src += 1;
	buf = calloc(strlen(*src) + 1, 1);
	buf_ptr = buf;
	temp = buf;
	while (**src && count != 0)
	{
		*buf_ptr = **src;
		if (**src == '(')
			count++;
		else if (**src == ')')
			count--;
		if (count != 0)
			buf_ptr += 1;
		else
			*buf_ptr = 0;
		*src += 1;
	}
	recursive_token(buf, list, 0, 0);
	free(temp);
}

void add_list_data(char **s, int token, t_tok_list *list)
{
	list->str = *s;
	list->token = token;
}



//condition == 0 still can run;
//condition == 1 move to next loop;
//condition == 2 break loop;

int	if_space(char *src, int *condition)
{
	if (*condition == 1)
		return 1;
	if (ft_is_space(*src))
	{
		*condition = 2;
		return 2;
	}
	return (0);
}

void	if_meet_quote(char **src, char **ptr, int *token, int *condition)
{
	recursive_token_quote_helper(src, ptr, token);
	*condition = 1;
}

int	if_meet_redir(char **src, char **ptr, int *token, char **buf)
{
	
		if (**buf == 0 || ft_strnum(*buf))
			recursive_token_redir_helper(src, ptr, token);
		if (strchr("\"\'", **src) == 0)
			return (2);
		src[0] -= 1;
		return (1);
}

int	if_meet_paren(char **src, int *token, t_tok_list **branch, char **buf)
{
	if (**src == ')')
		src[0] += 1;
	else if (**buf == 0)
		recursive_token_paren_helper(src, token, &(*branch)->child);
	return (2);
}

int if_meet_condition(char **src, char **ptr, int *token, char **buf)
{
	if (**buf == 0)
	{
		recursive_token_cond_helper(src, ptr, token);
		if (*token)
			return (2);
		src--;
		return (1);
	}
	return (2);
}

void	setup_recursive_token(char *src, char **buf, char **ptr, t_tok_list **branch)
{
	*buf = calloc(strlen(src) + 1, 1);
	*branch = ft_new_toklist();
	*ptr = *buf;
}

int	recursive_token_skip_space(char **src, int *utils)
{
	utils[0] = 0;
	utils[1] = 0;
	while (**src && ft_is_space(**src))
		src[0] += 1;
	if (**src == 0)
		return (0);
	return (1);
}

void	recursive_token_send_next(char **src, char **buf, int *token, t_tok_list **branch)
{
	add_list_data(buf, *token, *branch);
	if (src && *src != 0)
		recursive_token(*src, &(*branch)->next, 0, 0);
}

int	recursive_token_setup_loop(char **src, int *condition)
{
	if (*condition == 2)
		return (0);
	*condition = 0;
	src[0] += 1;
	return (1);
}

void recursive_token(char *src, t_tok_list **branch, int root_call, char *temp)
{
	char *buf;
	char *ptr;
	int	utils[2];

	if (recursive_token_skip_space(&src, utils) == 0)
		return ;
	setup_recursive_token(src, &buf, &ptr, branch);
	while (*src)
	{
		if (if_space(src, &utils[0]) == 2)
			break;
		else if (utils[0] == 0 && strchr("\"\'", *src))
			if_meet_quote(&src, &ptr, &utils[1], &utils[0]);
		else if (utils[0] == 0 && strchr("<>", *src))
			utils[0] = if_meet_redir(&src, &ptr, &utils[1], &buf);
		else if (utils[0] == 0 && strchr("|&", *src))
			utils[0] = if_meet_condition(&src, &ptr, &utils[1], &buf);
		else if (utils[0] == 0 &&strchr("()", *src))
			utils[0] = if_meet_paren(&src, &utils[1], branch, &buf);
		else if (utils[0] == 0)
			*ptr++ = *src;
		if (recursive_token_setup_loop(&src, &utils[0]) == 0)
			break;
	}
	recursive_token_send_next(&src, &buf, &(utils[1]),branch);
}

// ----------- group by exec ---------

// ---------------- end of token part -----

// ---------------- valid_check ----------

int valid_raw_data(t_tok_list *data, int *error)
{
	int new_error;

	if (data == NULL)
		return 0;
	new_error = 0;
	if (data->token == ERROR_TYPE)
	{
		write(2, "minishell : syntax error unexpected token at `", 46);
		if (data->str)
			write(2, data->str, strlen(data->str));
		else
			write(2, "<n/a>", 5);
		write(2, "`\n", 2);
		(*error)++;
		return (2);
	}
	error += valid_raw_data(data->child, error);
	error += valid_raw_data(data->next, error);
	return (new_error);
}

void ft_free_tok_list(t_tok_list *head)
{
	if (head == NULL)
		return ;
	if (head->child)
	{
		printf("child -->\n");
		ft_free_tok_list(head->child);
		head->child = NULL;
		printf("finish child -->\n");
	}
	if (head->next)
	{
		printf("next -->\n");
		ft_free_tok_list(head->next);
		head->next = NULL;
		printf("finish next -->\n");
	}
	if (head->str)
	{
		printf("del __%s__\n", head->str);
		free(head->str);
		head->str = NULL;
	}
	printf("struct\n");
	free(head);
	head = NULL;
}

// -----------tok test---------
void	test_tok(t_tok_list *head)
{
	if (head->child)
	{
		printf("goto _child\n");
		test_tok(head->child);
	}
	if (head->str)
		printf("%s\n", head->str);
	if (head->next)
	{
		printf("goto _next\n");
		test_tok(head->next);
	}
}

// ---------- test exec -----

void	exec_test(t_exec *head)
{
	if (head->child)
	{
		printf("goto child\n");
		exec_test(head->child);
		printf("end of traverse_child\n");
	}
	else
	{
		while (head->cmd)
		{
			printf("%s\n",head->cmd->s);
			head->cmd = head->cmd->next;
		}
		printf("_____\n");
		while (head->redir)
		{
			printf("%s\n", head->redir->front_fd);
			printf("%s\n", head->redir->back_fd);
			head->redir = head->redir->next;
		}
	}
	if (head->next)
	{
		printf("goto next\n");
		exec_test(head->next);
		printf("end of traverse end next\n");
	}
}
// --- recursive head ------
t_tok_list *group_per_exec(char *src)
{
	t_tok_list *tok_head;
	int temp;

	temp = 0;
	tok_head = NULL;
	recursive_token(src, &tok_head, 1, 0);
	free(src);
	src = NULL;
	if (valid_raw_data(tok_head, &temp) != 0)
	{
		ft_free_tok_list(tok_head);
		tok_head = NULL;
		return (0);
	}
	// test_tok(tok_head);
	// printf("__print end tok__\n");
	return (tok_head);
}

// ---------------------- finish part seperate -------

// ------------------------------build in -----------------------

int buildin_export(t_map_list *env, char **cmd, int status, int condition);

//// ------------cd--------------
char	*resolve_absolute_path(char *path, t_map_list *env, char *str_temp)
{
	char cwd[800];
	char *temp[3];
	char *resolved_path;

	resolved_path = strdup(path);
	temp[0] = "export";
	str_temp = calloc(strlen(resolved_path) + 5, 1);
	strcat(str_temp, "PWD=");
	strcat(str_temp, resolved_path);
	temp[1] = str_temp;
	temp[2] = NULL;
	buildin_export(env, temp, 0, 0);
	free(str_temp);
	if (getcwd(cwd, sizeof(cwd)) == NULL)
		return (resolved_path);
	str_temp = calloc(strlen(cwd) + 8, 1);
	strcat(str_temp, "OLDPWD=");
	strcat(str_temp, cwd);
	temp[1] = str_temp;
	buildin_export(env, temp, 0, 0);
	free(str_temp);
	return (resolved_path);
}

char	*ft_getcwd_error()
{
	perror("cd: error retrieving current directory: getcwd: cannot "
		   "access parent directories");
	return (NULL);
}


char *ft_getenv(char *s, t_map_list *env, int status);  //:FIX:
void	export_pwd_oldpwd(char *res_path, t_map_list *env, char *dir_path, char *target) // :FIX:
{
	char *temp[3];
	char *str_temp;
	char *pwd_temp;

	temp[0] = "export";
	temp[2] = NULL;
	pwd_temp = ft_getenv("PWD", env, 0);
	str_temp = (char *)calloc(strlen(pwd_temp) + 8, 1);
	strcat(str_temp, "OLDPWD=");
	strcat(str_temp, pwd_temp);
	temp[1] = str_temp;
	buildin_export(env, temp, 0, 0);
	free(str_temp);
	// if (strcmp(pwd_temp, dir_path) == 0)
	// 	return ;
	str_temp = (char *)calloc(strlen(res_path) + 5, 1);
	strcat(str_temp, "PWD=");
	strcat(str_temp, res_path);
	temp[1] = str_temp;
	buildin_export(env, temp, 0, 0);
	free(str_temp);
}

char	*resolve_relative_path(char *path, t_map_list *env, char *str_temp)  //:FIX:
{
	char cwd[800];
	char *temp[3];
	char	*resolved_path;

	if (getcwd(cwd, sizeof(cwd)) == NULL)
		return (ft_getcwd_error());
	resolved_path = (char *)calloc(strlen(cwd) + strlen(path) + 2, 1);
	strcpy(resolved_path, cwd);
	strcat(resolved_path, "/");
	strcat(resolved_path, path);
	export_pwd_oldpwd(resolved_path, env, cwd, path);
	return (resolved_path);
}

int	get_back_slash_n(char *src)
{
	int	count;

	count = 0;
	while (*src)
	{
		if (*src == '/' && src[1])
			count++;
		src++;
	}
	return (count);
}

char	*find_up_dir(char *src)
{
	char *ptr;
	int count;

	count = get_back_slash_n(src);
	ptr = src;
	while (count)
	{
		if (*ptr == '/')
		{
			if (ptr[1] && ptr[1] == '.' && ptr[2] && (ptr[2] == 0 || ptr[2] == '/'))
			{
				while (ptr > src)
				{
					ptr--;
					if (*ptr == '/')
						break;
				}
			}
			count--;
		}
		ptr++;
	}
	return ptr;
}


char *resolve_up_path(char *path, t_map_list *env)
{
	char cwd[800];
	char	*temp;
	char	*res;
	char	*ptr;

	if (getcwd(cwd, sizeof(cwd)) == NULL)
		temp = ft_getenv("PWD", env, 0);
	else
		temp = strdup(cwd);
	ptr = find_up_dir(temp);
	res = strndup(temp, ptr - temp);

	export_pwd_oldpwd(res, env, cwd, path);
	// chdir(res);
	return (res);
}

char *resolve_path(char *path, t_map_list *env)
{
	char *resolved_path = NULL;

	if (path[0] == '/')
		return (resolve_absolute_path(path, env, 0));
	else if (strcmp(path, "..") == 0 || strcmp(path, "../") == 0)
		return (resolve_up_path(path, env));
	else
		return (resolve_relative_path(path, env, 0));
}

// ------------------------- fin
char *ft_getenv(char *s, t_map_list *env, int status);

int	back_to_old_pwd(char **str_temp, char **res_path ,t_map_list *env)
{
	*str_temp = ft_getenv("OLDPWD", env, 0);
	if (*str_temp == 0 || **str_temp == 0)
	{
		free(*str_temp);
		write(2, "minishell: cd: OLDPWD not set\n", 30);
		return (1);
	}
	*res_path = strdup(*str_temp);
	free(*str_temp);
	return (0);
}

int	buildin_cd_manage_return(char **res_path, t_exec *data)
{
	if (*res_path == NULL)
		return (0);
	if (chdir(*res_path) != 0)
	{
		free(*res_path);
		*res_path = NULL;
		write(2, "minishell: cd: ", 15);
		perror(data->cmd->next->s);
		return (1);
	}
	free(*res_path);
	*res_path = NULL;
	return (0);
}

int	ft_cd_root_dir_error()
{
	write(2, "minishell: cd: can't go back to root dir\n", 41);
	return (0);
}

int	ft_cd_getcwd_error(char **s)
{
	if (*s)
		free(*s);
	*s = NULL;
	perror("cd: error retrieving current directory: getcwd: cannot "
		   "access parent directories");
	return 1;
}

char	*buildin_cd_add_pwd(t_map_list *env)
{
	char	*temp[3];
	char	*str_temp;
	char	*res_temp;

	temp[0] = "export";
	str_temp = ft_getenv("HOME", env, 0);
	res_temp = calloc(strlen(str_temp) + 5, 1);
	strcat(res_temp, "PWD=");
	strcat(res_temp, str_temp);
	free(str_temp);
	temp[2] = NULL;
	temp[1] = res_temp;
	buildin_export(env, temp, 0, 0);
	return (res_temp);
}

int buildin_cd(t_exec *data, t_map_list *env, char *res_path, char *str_temp)
{
	char *temp[3];
	char cwd[800];
	int	error;

	if (data->cmd->next == 0 || data->cmd->next->s == 0 || data->cmd->next->s[0] == 0)
	{
		if (chdir(getenv("HOME")) != 0)
			return (ft_cd_root_dir_error());
		temp[1] = buildin_cd_add_pwd(env);
		if (getcwd(cwd, sizeof(cwd)) == NULL)
			return (ft_cd_getcwd_error(&temp[1]));
		if (temp[1])
			free(temp[1]);
		return (0);
	}
	else if (data->cmd->next && data->cmd->next->s && data->cmd->next->s[0] == '-' &&
			 data->cmd->next->s[1] == 0 && back_to_old_pwd(&str_temp, &res_path, env) == 1)
			return (1);
	else
		res_path = resolve_path(data->cmd->next->s, env);
	return (buildin_cd_manage_return(&res_path, data));
}

//// ------- echo ------------------------------------
int buildin_echo(char **cmd)
{
	int count;
	int j;
	int no_newline;
	char *temp;

	j = 1;
	no_newline = 0;
	while (cmd[j] && strcmp("-n", cmd[j]) == 0)
	{
		no_newline = 1;
		j++;
	}
	while (cmd[j])
	{
		printf("%s", cmd[j]);
		if (cmd[j + 1])
			printf(" ");
		j++;
	}
	if (no_newline == 0)
		printf("\n");
	return (0);
}

//// -------- pwd ----------------------------------
int buildin_pwd(t_map_list *head)
{
	char cwd[400];
	char	*pwd;

	pwd = ft_getenv("PWD", head, 0);
	if (pwd == NULL)
	{
		getcwd(cwd, sizeof(cwd));
		printf("%s\n", cwd);
	}
	else
	{
		printf("%s\n", pwd);
		free(pwd);
	}
	return (0);
}

////
//// -------- export ------------------------------

int char_valid(char c)
{
	if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' ||
		c == '+' || (c >='0' && c <= '9'))
		return (1);
	return (0);
}

int	handle_delimiter(char *cmd, size_t *i, int *append)
{
	while (cmd[*i] && cmd[*i] != '=')
	{
		if (char_valid(cmd[*i]) == 0)
			return (0);
		if (cmd[*i] == '+')
		{
			if (cmd[*i + 1] && cmd[*i + 1] == '=')
				*append = 1;
			else
				return (0);
		}
		*i += 1;
	}
	return (1);
}

int check_export_valid(char *cmd)
{
	size_t i;
	int append;

	append = 0;
	i = 0;
	if (strchr("!@#$%^&*()+=\\-\"'{[]}$?&:;~`.,/*1234567890", cmd[0]))
		return (0);
	if (handle_delimiter(cmd, &i, &append) == 0)
		return (0);
	if (i == 0)
		return (0);
	else if (i == 1)
	{
		if (strchr("!@#$%^&*()+=\\-\"'{[]}$?&:;~`.,/*", cmd[0]))
			return (0);
	}
	if (append == 1)
		return (2);
	return (1);
}

void print_export(t_map_list *env)
{
	while (env)
	{
		printf("declare -x %s=\"%s\"\n", env->key, env->value);
		env = env->next;
	}
}

void ft_free_chrarr(char **arr);

void	append_env(char **new, char **data, t_map_list *env)
{
	strcat(*new, env->value);
	strcat(*new, data[1]);
	if (env->value)
		free(env->value);
	env->value = *new;
}

int is_env_dup(t_map_list *env, char **data, int condition)
{
	while (env)
	{
		if (strcmp(env->key, data[0]) == 0)
		{
			if (condition == 1)
			{
				char *new = calloc(strlen(env->value) + strlen(data[1]) + 1, 1);
				append_env(&new, data, env);
			}
			else
			{
				if (env->value)
					free(env->value);
				if (data[1])
					env->value = strdup(data[1]);
			}
			return (1);
		}
		env = env->next;
	}
	return (0);
}

void	export_one_condition(char **cmd, size_t *j, char **res, t_map_list *env)
{
	int	i;
	char	*cmd_temp;
	size_t temp;

	i = 0;
	cmd_temp = cmd[*j];
	temp = strchr(cmd_temp, '=') - cmd[*j];
	res = (char **)calloc(3, sizeof(char *));
	res[0] = calloc(temp + 1, 1);
	res[1] = calloc((strlen(cmd_temp) - temp) + 1, 1);
	res[2] = NULL;
	while (*cmd_temp != '=')
		res[0][i++] = *cmd_temp++;
	cmd_temp++;
	i = 0;
	while (*cmd_temp)
		res[1][i++] = *cmd_temp++;
	if (is_env_dup(env, res, 0) == 0)
		ft_add_maplist(&env, res);
	if (res)
	{
		ft_free_chrarr(res);
		free(res);
	}
	res = NULL;
}
void	export_sec_condition(char **cmd, size_t *j, char **res, t_map_list *env)
{
	int	i;
	char	*cmd_temp;
	size_t temp;

	i = 0;
	cmd_temp = cmd[*j];
	temp = strchr(cmd_temp, '+') - cmd[*j];
	res = (char **)calloc(3, sizeof(char *));
	res[0] = calloc(temp + 2, 1);
	res[1] = calloc((strlen(cmd_temp) - temp) + 2, 1);
	res[2] = NULL;
	while (*cmd_temp != '+')
		res[0][i++] = *cmd_temp++;
	cmd_temp += 2;
	i = 0;
	while (*cmd_temp)
		res[1][i++] = *cmd_temp++;
	if (is_env_dup(env, res, 1) == 0)
		ft_add_maplist(&env, res);
	if (res)
	{
		ft_free_chrarr(res);
		free(res);
	}
	res = NULL;
}

void	buildin_export_error(char **cmd, int index, int *status)
{
	write(STDERR_FILENO, "minishell: export: ", 19);
	write(STDERR_FILENO, cmd[index], strlen(cmd[index]));
	write(STDERR_FILENO, ": not a valid identifier\n", 25);
	*status = 1;
}


int buildin_export(t_map_list *env, char **cmd, int status, int condition)
{
	char **res;
	size_t j;

	res = NULL;
	if (cmd[1] == 0)
		return (print_export(env), EXIT_SUCCESS);
	j = 1;
	while (cmd[j])
	{
		condition = check_export_valid(cmd[j]);
		if (condition)
		{
			if ((cmd[j] == NULL && cmd[j] == 0) ||(strchr(cmd[j], '=') == NULL))
				break;
			if (condition == 1)
				export_one_condition(cmd, &j, res, env);
			else if (condition == 2)
				export_one_condition(cmd, &j, res, env);
		}
		else
			buildin_export_error(cmd, j, &status);
		j++;
	}
	return status;
}

//// ----------------- env ------------
int buildin_env(t_map_list *env, char **cmd)
{
	int size;

	size = 0;
	while (cmd[size])
		size++;
	if (size > 1)
	{
		write(STDERR_FILENO, "env: ", 5);
		write(STDERR_FILENO, cmd[1], strlen(cmd[1]));
		write(STDERR_FILENO, ": No such file or directory\n", 28);
		return (EXIT_FAILURE);
	}
	while (env)
	{
		printf("%s=%s\n", env->key, env->value);
		env = env->next;
	}
	return (EXIT_SUCCESS);
}

//// ------------ unset --------------
void ft_node_cmp_remove(t_map_list **env, char *str)
{
	t_map_list *temp;
	t_map_list *remove_pos;
	if (*env == NULL)
		return;
	if (strcmp((*env)->key, str) == 0)
	{
		temp = *env;
		*env = (*env)->next;
		free(temp->key);
		temp->key = NULL;
		free(temp->value);
		temp->value = NULL;
		free(temp);
		temp = NULL;
		return;
	}
	ft_node_cmp_remove(&(*env)->next, str);
}

int check_valid_unset(char *s)
{
	size_t i;

	i = 0;
	if (strchr("~!@#$%^&*()+1234567890-={}[]\\|:;?/.,<>`", s[i]))
		return (0);
	i++;
	while (s[i] && strchr("!@#$%^&*()+--=\'\"\\|:;/?<>~`~`[]{}", s[i]) == NULL)
		i++;
	if (s[i])
		return (0);
	return (1);
}

int buildin_unset(t_map_list **env, char **cmd)
{
	size_t i;
	int status;

	i = 1;
	status = 0;
	while (cmd[i])
	{
		if (cmd[i][0] && check_valid_unset(cmd[i]))
			ft_node_cmp_remove(env, cmd[i]);
		else
		{
			status = 1;
			write(2, "minishell: unset: `", 19);
			write(2, cmd[i], strlen(cmd[i]));
			write(2, "`: not a valid identifier\n", 26);
		}
		i++;
	}
	return (status);
}

// ------------- exit ----------------
int ft_strnum_exit(char *s)
{
	int count = 0;

	if (s == NULL || *s == 0)
		return (0);
	if (strchr("-+", *s))
		s++;
	while (*s)
	{
		count++;
		if ((*s >= '0' && *s <= '9'))
			s++;
		else
			break;
	}
	if (*s == 0 && count)
		return (1);
	return (0);
}

long long ft_atoll(char *s)
{
	long long state;
	long long res;

	state = 0;
	res = 0;
	if (*s == '-')
		state = 1;
	if (*s == '-' || *s == '+')
		s++;
	while (*s >= '0' && *s <= '9')
		res = (res * 10) + (*s++ - '0');
	if (state)
		return (res * -1);
	if (res > 9223372036854775807 || res < -9223372036854775807)
		return (255);
	return (res);
}

int	over_llong_minus(char *s)
{
	char *llong;
	llong = "9223372036854775808";

	if (strlen(s) < 19)
		return (VALID_LLONG);
	else if (strlen(s) >= 20 || strcmp(s, llong) > 0)
		return (-1);
	else if (strcmp(s, llong) == 0)
		return (0);
	return (VALID_LLONG);
}

int over_llong_plus(char *s)
{
	char *llong;
	llong = "9223372036854775807";

	if (strlen(s) >= 20)
		return (-1);
	else if (strlen(s) < 19)
		return (VALID_LLONG);
	if (strcmp(s, llong) >= 0)
		return (-1);
	return (VALID_LLONG);
}

int handle_over_llong(char *s)
{
	int i;

	if (*s == '-')
	{
		s++;
		while (*s && *s == '0')
			s++;
		return (over_llong_minus(s));
	}
	else
	{
		while (*s && *s == '0')
			s++;
		return (over_llong_plus(s));
	}
	return (VALID_LLONG);
}

int	buildin_exit_args_err(int *status)
{
	write(2, "minishell: exit: too many arguments\n", 36);
	*status = 1;
	return *status;
}

void	buildin_exit_alp_arg(char **cmd, int *status)
{
	write(2, "exit: ", 6);
	write(2, cmd[1], strlen(cmd[1]));
	write(2, ": numeric argument required\n", 28);
	*status = 255;
}

int buildin_exit(char **cmd, int *status)
{
	int size;

	size = 0;
	while (cmd[size])
		size++;
	*status = 0;
	printf("exit\n");
	if (size == 1)
	{
		sigint_in = 2;
		return (*status);
	}
	else if (size > 2)
		return (buildin_exit_args_err(status));
	if (handle_over_llong(cmd[1]) != VALID_LLONG)
		*status = handle_over_llong(cmd[1]);
	else if (ft_strnum_exit(cmd[1]))
		*status = ((unsigned char)ft_atoll(cmd[1]));
	else if (cmd[1])
		buildin_exit_alp_arg(cmd, status);
	sigint_in = 2;
	return ((unsigned char)*status);
}

char **get_cmd_arr(t_list *cmd, t_map_list *env, int status);

void run_buildin_cmd(t_exec *data, int *status, t_map_list **env, char **cmd)
{
	int i = 0;

	if (strcmp("echo", cmd[0]) == 0)
		*status = buildin_echo(cmd);
	if (strcmp("cd", cmd[0]) == 0)
		*status = buildin_cd(data, *env, 0, 0);
	else if (strcmp("pwd", cmd[0]) == 0)
		*status = buildin_pwd(*env);
	else if (strcmp("export", cmd[0]) == 0)
		*status = buildin_export(*env, cmd, 0, 0);
	else if (strcmp("unset", cmd[0]) == 0)
		*status = buildin_unset(env, cmd);
	else if (strcmp("env", cmd[0]) == 0)
		*status = buildin_env(*env, cmd);
	else if (strcmp("exit", cmd[0]) == 0)
		*status = buildin_exit(cmd, status);
}

int check_buildin(char *cmd)
{
	if (strcmp("echo", cmd) == 0)
		return 1;
	if (strcmp("cd", cmd) == 0)
		return 1;
	else if (strcmp("pwd", cmd) == 0)
		return 1;
	else if (strcmp("export", cmd) == 0)
		return 1;
	else if (strcmp("unset", cmd) == 0)
		return 1;
	else if (strcmp("env", cmd) == 0)
		return 1;
	else if (strcmp("exit", cmd) == 0)
		return 1;
	return 0;
}

// ---------------------- exec thing -----------------
t_exec *make_new_exec(void)
{
	t_exec *new;

	new = (t_exec *)malloc(sizeof(t_exec));
	new->run_condition = 0;
	new->child = NULL;
	new->cmd = NULL;
	new->redir = NULL;
	new->next = NULL;
	return (new);
}

int get_type_size(int type, t_tok_list *data)
{
	int res;

	res = 0;
	while (data && data->token != PARENT_TYPE)
	{
		if (data->token == type)
			res++;
		data = data->next;
	}
	return (res);
}

void add_exec_args(t_exec *head, t_tok_list *data, int type)
{
	t_redirect *temp;

	temp = head->redir;
	while (temp->next)
		temp = temp->next;
}

t_redirect *ft_new_redir(void)
{
	t_redirect *new;

	new = malloc(sizeof(t_redirect));
	new->type = 0;
	new->front_fd = NULL;
	new->back_fd = NULL;
	new->next = NULL;
	new->heredoc = NULL;
	return (new);
}

int ft_atoi_strict(char *s)
{
	int res;

	res = 0;
	while (*s)
	{
		if (*s > '9' || *s < '0')
			return (-1);
		res = (res * 10) + (*s++ - '0');
	}
	return (res);
}

char *get_front_fd(char *s)
{
	char *buf;
	size_t i;
	size_t j;

	i = 0;
	j = 0;
	buf = NULL;
	while (!(*(s + i) == '>' || *(s + i) == '<'))
		i++;
	if (i != 0)
	{
		buf = calloc(i + 1, 1);
		while (j < i)
		{
			buf[j] = s[j];
			j++;
		}
	}
	return (buf);
}

int	get_type_redir_case(char *s, int i)
{
	if (s[i] == '>')
	{
		if (s[i + 1] && s[i + 1] == '>')
			return (APPEN);
		else if (s[i + 2] && s[i + 2] == '>')
			return (REDIR_ERR);
		else
			return (O_REDIR);
	}
	else if (s[i] == '<')
	{
		if (s[i + 1] && s[i + 1] == '<')
		{
			return (HERED);
		}
		else if (s[i + 2] && s[i + 2] == '>')
			return (REDIR_ERR);
		else
			return (I_REDIR);
	}
	return (0);
}

int get_type_redir(char *s)
{
	int i;

	i = 0;
	while (strchr("><", s[i]) == NULL)
		i++;
	if (s[i] == '>' || s[i] == '<')
		return (get_type_redir_case(s, i));
	return (-1);
}

int valid_numb_str(char *s)
{
	if (*s == 0)
		return (-1);
	while (*s >= '0' && *s <= '9')
		s++;
	if (*s)
		return (0);
	return (1);
}

char	*get_back_fd_from_next_node(t_tok_list **data, char *s)
{
	*data = (*data)->next;
	if (*data == NULL)
		return (NULL);
	if ((*data)->token != ARGS_TYPE)
		return (NULL);
	else
	{
		s = (*data)->str;
		*data = (*data)->next;
		return (strdup(s));
	}
}

char *get_back_fd(t_tok_list **data)
{
	char *s;
	int i;

	i = 0;
	s = (*data)->str;
	while (!(*(s + i) == '>' || *(s + i) == '<'))
		i++;
	while (*(s + i) == '>' || *(s + i) == '<')
		i++;
	if (*(s + i))
	{
		*data = (*data)->next;
		return (strdup(s + i));
	}
	else
	{
		return (get_back_fd_from_next_node(data, s));
	}
}

void add_exec_redir(t_exec *head, t_tok_list **data)
{
	t_redirect *temp;

	if (head->redir == NULL)
	{
		head->redir = ft_new_redir();
		head->redir->front_fd = get_front_fd((*data)->str);
		head->redir->type = get_type_redir((*data)->str);
		head->redir->back_fd = get_back_fd(data);
	}
	else
	{
		temp = head->redir;
		while (temp->next)
			temp = temp->next;
		temp->next = ft_new_redir();
		temp->next->front_fd = get_front_fd((*data)->str);
		temp->next->type = get_type_redir((*data)->str);
		temp->next->back_fd = get_back_fd(data);
	}
}

void ft_new_list_addback(t_list **head, char *s)
{
	t_list *temp;

	if (*head == NULL)
	{
		*head = malloc(sizeof(t_list));
		temp = *head;
	}
	else
	{
		temp = *head;
		while (temp->next != NULL)
			temp = temp->next;
		temp->next = malloc(sizeof(t_list));
		temp = temp->next;
	}
	temp->s = strdup(s);
	temp->next = NULL;
}

int get_condition(char *data)
{
	if (strcmp(data, "||") == 0)
		return (OP_OR);
	if (strcmp(data, "&&") == 0)
		return (OP_AND);
	if (strcmp(data, "|") == 0)
		return (PIPE);
	return (0);
}

void get_exec_data(t_tok_list *data, t_exec **head);

// void	i_need_25_line_long_so_i_made_this_fn(t_tok_list **data, t_exec **child)
// {
// 	get_exec_data((*data)->child, child);
// 	*data = (*data)->next;
// }

void get_exec_data(t_tok_list *data, t_exec **head)
{
	t_exec *temp;

	if (data == NULL)
		return ;
	if (*head == NULL)
		*head = make_new_exec();
	temp = *head;
	while (data)
	{
		if (data->token == PARENT_TYPE)
		{
			// printf("make child\n");
			get_exec_data(data->child, &temp->child);
			if (data->next && data->next->token == PARENT_TYPE)
			{
				// printf("make child\n");
				get_exec_data(data->next, &temp->next);
				return ;
			}
			else
			{
				if (data->next)
					get_exec_data(data->next, head);
				return ;
			}
			// if (data->next)
			// 	get_exec_data(data->next, &temp->next);
			// return ;
			// temp = temp->next;
			// data = data->next;
		}
		else if (data->token == REDIR_TYPE)
			add_exec_redir(*head, &data);
		else if (data->token == CONDITION_TYPE)
		{
			(*head)->run_condition = get_condition(data->str);
			get_exec_data(data->next, &temp->next);
			return;
		}
		else if (data->token == ARGS_TYPE)
		{
			ft_new_list_addback(&temp->cmd, data->str);
			data = data->next;
		}
	}
}

int recheck_redir(t_tok_list *list)
{
	int i;

	i = 0;
	if (list == NULL)
		return (0);
	if (list->token == REDIR_TYPE)
	{
		if (strstr(list->str, ">>>"))
			i++;
		else if (strstr(list->str, "<<<"))
			i++;
	}
	if (list->child)
		i += recheck_redir(list->child);
	if (list->next)
		i += recheck_redir(list->next);
	return (i);
}

int check_child(char *s)
{
	if (s == 0 || *s == 0)
	{
		write(2, "minishell : syntax error near unexpected token `", 48);
		write(2, "newline", 7);
		write(2, "`\n", 2);
		return (0);
	}
	while (*s == ' ')
		s++;
	if (*s && (strchr("()|/<>#", *s)))
	{
		write(2, "minishell : syntax error near unexpected token `", 48);
		write(2, s, 1);
		write(2, "`\n", 2);
		return (0);
	}
	return (1);
}

int	check_redir_valid_error(int redir)
{
	write(2, "minishell : syntax error unexpected token at `", 46);
	write(2, &redir, 1);
	write(2, "`\n", 2);
	return (0);
}

void	move_ptr_in_quote(int *token, char **str)
{
	*token = **str;
	*str += 1;
	while (**str && **str != *token)
		*str += 1;
	if (*str == 0)
		*str -=1;
}

void	skip_redir(char **str, int *count, int *redir)
{
	*redir = **str;
	while (**str == *redir)
	{
		*count += 1;
		*str += 1;
	}
}

int check_redir_valid(char *str)
{
	int count;
	int token;
	int redir;

	count = 0;
	while (*str)
	{
		if (*str == '>' || *str == '<')
		{
			skip_redir(&str, &count, &redir);
			if (count > 2)
				return (check_redir_valid_error(redir));
			if (check_child(str) == 0)
				return (0);
			str--;
			count = 0;
		}
		else if (strchr("\'\"", *str))
			move_ptr_in_quote(&token, &str);
		if (count < 0)
			break;
		str++;
	}
	return (1);
}

// -----------------------------

// ----------------- get heredoc------

int get_status(int status);

void	heredoc_input_process(t_pipe *pipe_fd, char *eof)
{
	char *input;

	close((*pipe_fd).read_fd);
	sig_setup_heredoc();
	while (sigint_in == 0)
	{
		input = readline("heredoc> ");
		if (input == 0 || strcmp(input, eof) == 0 || sigint_in == 1)
		{
			free(input);
			break;
		}
		write((*pipe_fd).write_fd, input, strlen(input));
		write((*pipe_fd).write_fd, "\n", 1);
		free(input);
	}
	if (sigint_in == 1)
	{
		close((*pipe_fd).write_fd);
		exit(EXIT_FAILURE);
	}
	write((*pipe_fd).write_fd, "\n", 1);
	close((*pipe_fd).write_fd);
	exit(EXIT_SUCCESS);
}

int	heredoc_parent_handle_error(t_pipe *pipe_fd, char *eof, pid_t pid, int *res_status)
{
		int status;
		close((*pipe_fd).write_fd);
		waitpid(pid, &status, 0);
		sig_ignore();
		if (WIFSIGNALED(status))
		{
			close((*pipe_fd).read_fd);
			*res_status = 1;
			return 1;
		}
		else
			*res_status = 0;
	return (0);
}

void	heredoc_set_line(char **result, char **line, int line_count, int *i)
{
	strcat(*result, line[*i]);
	if (*i + 1 < line_count)
		strcat(*result, "\n");
	free(line[*i]);
	*i += 1;
}

char	*heredoc_set_data(t_pipe *pipe_fd, int line_count, size_t total_length)
{
	char buffer[1024];
	char *line[300];
	char *result;
	size_t byte_read;
	int	i;

	result = 0;
	byte_read = read((*pipe_fd).read_fd, buffer, sizeof(buffer));
	while (byte_read > 0)
	{
		line[line_count] = strndup(buffer, byte_read - 1);
		total_length += strlen(line[line_count]);
		line_count++;
		byte_read = read((*pipe_fd).read_fd, buffer, sizeof(buffer));
	}
	close((*pipe_fd).read_fd);
	result = (char *)calloc(total_length + line_count, 1);
	i = 0;
	while (i < line_count)
		heredoc_set_line(&result, line, line_count, &i);
	return result;
}

char *add_heredoc(char *eof, int *res_status)
{
	t_pipe pipe_fd;
	size_t total_length = 0;
	pid_t pid;

	if (pipe((int *)&pipe_fd) == -1)
	{
		perror("pipe create error");
		exit(EXIT_FAILURE);
	}
	pid = fork();
	if (pid == 0)
		heredoc_input_process(&pipe_fd, eof);
	else
	{
		if (heredoc_parent_handle_error(&pipe_fd, eof, pid, res_status) == 1)
			return (NULL);
		return (heredoc_set_data(&pipe_fd, 0, 0));
	}
	return (NULL);
}

t_list *get_replaced(char *str, t_map_list *env, int status);

int is_parse_able(char *s);

char *replace_addback(char *str, size_t *index, t_map_list *env,
					 int status);


void	setup_search_replace(bool *s_quote, bool *d_quote, size_t *i)
{
	*s_quote = false;
	*d_quote = false;
	*i = 0;
}

void	replace_addback_manage(char *str, size_t *i, bool *in_quote)
{
	if (str[0][i] == '\'' && in_quote[1] == false && *i++ != -1)
	{
		*i += 1;
		in_quote[0] = !in_quote[0];
	}
	else if (str[0][i] == '\"' && in_quote[0] == false && *i != -1)
	{
		*i += 1;
		in_quote[1] = !in_quote[1];
	}
}

void	update_and_free(t_list **res,char **temp, char **str, size_t *i)
{
	ft_new_list_addback(res, *temp);
	if (*temp)
		free(*temp);
	*temp = NULL;
	str[0] += *i;
	*i = 0;
}

int	loop_search_replace(char **str, t_map_list *env, int status, t_list **res)
{
	bool in_quote[2];
	size_t	i;
	char *temp;

	setup_search_replace(&in_quote[0], &in_quote[1], &i);
	while (str[0][i])
	{
		if ((str[0][i] == '\'' && in_quote[1] == false && i++ != -1) ||
			(str[0][i] == '\"' && in_quote[0] == false && i++ != -1))
			replace_addback_manage(*str, &i, in_quote);
		else if (str[0][i] == '$' && str[0][i + 1] && ft_is_space(str[0][i + 1]) == 0 &&
				 strchr("\"\'=()", str[0][i + 1]) == 0)
		{
			temp = strndup(*str, i);
			ft_new_list_addback(res, temp);
			if (temp)
				free(temp);
			temp = replace_addback(*str, &i, env, status);
			update_and_free(res, &temp, str, &i);
		}
		else
			i++;
	}
	return (i);
}

t_list *get_heredoc_replaced(char *str, t_map_list *env, int status)
{
	t_list *res;
	size_t i;
	char *temp;
	bool in_s_quote;
	bool in_d_quote;

	i = 0;
	res = NULL;
	in_s_quote = false;
	in_d_quote = false;
	i = loop_search_replace(&str, env, status, &res);
	if (i)
	{
		temp = strdup(str);
		ft_new_list_addback(&res, temp);
		free(temp);
	}
	return (res);
}

int	setup_replace_hered_str(char **str, t_map_list *env, int status, t_list **head)
{
	if (*str == 0 || **str == 0 || is_parse_able(*str) == 0)
		return (1);
	*head = get_heredoc_replaced(*str, env, status);
	if (*head == NULL)
		return (1);
	return (0);
}

void replace_hered_str(char **str, t_map_list *env, int status)
{
	t_list *head;
	size_t len;
	t_list *temp;
	char *res;
	char *str_temp;

	len = 0; /// one line of hell
	if (setup_replace_hered_str(str, env, status, &head) == 1)
		return ;
	temp = head;
	while (temp)
	{
		if (temp->s && temp->s[0])
			len += strlen(temp->s);
		temp = temp->next;
	}
	res = calloc(len + 1, 1);
	while (head)
	{
		if (head->s && head->s[0])
			strcat(res, head->s);
		head = head->next;
	}
	free(*str);
	*str = res;
}


int	check_parsing_eof(char **eof, t_redirect **temp, int *status, t_map_list *env)
{
	int not_parse;

	not_parse = 0;
	if (strchr(*eof, '\'') || strchr(*eof, '\"'))
	{
		not_parse = 1;
		unquote_realloc_str(eof);
	}
	(*temp)->heredoc = add_heredoc(*eof, status);
	if (*eof)
	{
		free(*eof);
		*eof = NULL;
	}
	if (*status != 0)
		return (1);
	else if (not_parse == 0)
		replace_hered_str(&(*temp)->heredoc, env, *status);
	return (0);
}

void	get_eof_from_next_args(t_exec *list, char **eof)
{
	if (list->next == NULL ||
		list->cmd->s == NULL)
		exit(EXIT_FAILURE);
	else
		*eof = strdup(list->cmd->s);
}

int	get_heredoc_loop(t_exec *exec_temp, int *status, t_map_list *env)
{
	t_redirect *temp;
	char *eof;

	temp = exec_temp->redir;
	while (temp)
	{
		if (temp->type == HERED)
		{
			if (temp->back_fd)
				eof = strdup(temp->back_fd);
			else
				get_eof_from_next_args(exec_temp, &eof);
			if (check_parsing_eof(&eof, &temp, status, env) == 1)
				return (1);
		}
		temp = temp->next;
	}
	return (0);
}

int get_heredoc(t_exec *head, t_map_list *env, int *status)
{
	t_redirect *temp;
	t_exec *exec_temp;

	if (head == NULL)
		return 0;
	exec_temp = head;
	while (exec_temp)
	{
		if (exec_temp->child)
			get_heredoc(exec_temp->child, env, status);
		if (exec_temp->redir)
		{
			if (get_heredoc_loop(exec_temp, status, env) == 1)
				return (1);
		}
		exec_temp = exec_temp->next;
	}
	return (0);
}


int	bad_condition_child(t_tok_list *list)
{
	if (list->token == CONDITION_TYPE && list->child == NULL)
	{
		write(2, "minishell : syntax error near unexpected token `", 48);
		if (list->str)
			write(2, list->str, strlen(list->str));
		write(2, "`\n", 2);
		return (1);
	}
	return (0);
}

int check_condition_valid(t_tok_list *list);

int	setup_buf_check_condition(t_tok_list *list, int *buf)
{
	*buf = 0;
	if (list->child)
	{
		*buf = check_condition_valid(list->child);
		if (*buf)
			return (1);
	}
	return (0);
}

int	fake_condition(t_tok_list *list)
{
	write(2, "minishell : syntax error near unexpected token `",
		  48);
	if (list->str)
		write(2, list->str, 1);
	write(2, "`\n", 2);
	return (1);
}

int	dup_or_nullafter_condition(t_tok_list *list)
{
	write(2, "minishell : syntax error near unexpected token `",
		  48);
	if (list->str)
		write(2, list->str, strlen(list->str));
	write(2, "`\n", 2);
	return (1);
}

int	setup_and_run_check_for_child(t_tok_list *list, int *buf)
{
	if (setup_buf_check_condition(list, buf) == 1)
		return (1);
	if (bad_condition_child(list) == 1)
		return (1);
	return (0);
}

int check_condition_valid(t_tok_list *list)
{
	int buf;

	buf = 0;
	if (setup_and_run_check_for_child(list, &buf))
		return (1);
	while (list)
	{
		if (list->child)
		{
			buf = check_condition_valid(list->child);
			if (buf)
				return (1);
		}
		else if (list->token == CONDITION_TYPE)
		{
			if (((strcmp("|", list->str) == 0 || strcmp("||", list->str) == 0 ||
				  strcmp("&&", list->str) == 0)) == 0)
				return (fake_condition(list));
			if ((list->next && list->next->token == CONDITION_TYPE) ||
				list->next == NULL)
				return (dup_or_nullafter_condition(list));
		}
		list = list->next;
	}
	return (0);
}

int	no_file_name_or_redir_num(t_exec *node)
{
	write(
		2,
		"minishell : syntax error near unexpected token `",
		48);
	if (node->next)
		write(2, " `\n", 3);
	else
		write(2, "newline`\n", 9);
	return (0);
}

int check_redir_valid_exec(t_exec *node)
{
	t_redirect *temp;

	while (node)
	{
		if (node->redir)
		{
			temp = node->redir;
			while (temp)
			{
				if (temp->back_fd == 0 ||
					(temp->back_fd && temp->back_fd[0] == 0))
				{
					if (node->next && node->next->cmd && node->next->cmd->s &&
						node->next->cmd->s[0] && node->next->child == NULL)
						return (1);
					else
						return (no_file_name_or_redir_num(node));
				}
				temp = temp->next;
			}
		}
		node = node->next;
	}
	return (1);
}

int	check_extra_redir_errone(t_tok_list *temp_list)
{
	if (temp_list)
	{
		ft_free_tok_list(temp_list);
		temp_list = NULL;
	}
	return (0);
}

int	check_extra_redir_errtwo(t_tok_list *temp_list)
{
	ft_free_tok_list(temp_list);
	temp_list = NULL;
	write(2, "minishell : syntax error near unexpected token `8`\n",51);
	return (0);
}

int	check_extra_redir_errthree(t_tok_list *temp_list, char *str, int index)
{
	if (str[index] == '&' && str[index] == 0)
	{
		ft_free_tok_list(temp_list);
		temp_list = NULL;
		write(2, "minishell : syntax error near unexpected token `",
			  48);
		write(2, "newline", 7);
		write(2, "`\n", 2);
		return (0);
	}
	return (1);
}

int	check_extra_redir_errfour(t_tok_list *temp_list, t_tok_list *list)
{
	if (list->next->str && list->next->str[0] == '&')
	{
		ft_free_tok_list(temp_list); // same
		temp_list = NULL;
		write(
			2,
			"minishell : syntax error near unexpected token `",
			48);
		write(2, &list->str[0], 1);
		write(2, "`\n", 2);
		return (0);
	}
	return (1);
}

int check_extra_redir_errfive(t_tok_list *temp_list, t_tok_list *list)
{
	if (list->next->str && list->next->str[0] == '&')
	{
		ft_free_tok_list(temp_list);
		temp_list = NULL;
		write(
			2,
			"minishell : syntax error near unexpected token `",
			48);
		write(2, &list->str[0], 1);
		write(2, "`\n", 2);
		return (0);
	}
}

int check_extra_redir_errsix(t_tok_list *temp_list, t_tok_list *list)
{
	ft_free_tok_list(temp_list);
	temp_list = NULL;
	write(2, "minishell : syntax error near unexpected token `",
		  48);
	if (list->next && list->next->str)
		write(2, list->next->str, strlen(list->next->str));
	else
		write(2, "newline", 7);
	write(2, "`\n", 2);
	return (0);
}

int sorry_i_no_have_name_left(t_tok_list *temp_list, t_tok_list *list)
{
	if (list->next && list->next->token == ARGS_TYPE)
	{
		if (check_extra_redir_errfour(temp_list, list) == 0)
			return (0);
		return (1);
	}
	else
		return (check_extra_redir_errsix(temp_list, list));
}

int	check_all_condition(t_tok_list *temp_list, t_tok_list *list, int *i)
{
	if (list->str[*i] && list->str[*i] == '&' && list->str[*i + 1] && (list->str[*i + 1] == '<' || (list->str[*i + 1] == '>' && list->str[*i + 2] && list->str[*i + 2] == '>'))) //:FIX:
		return (check_extra_redir_errtwo(temp_list));
	while (list->str[*i] && strchr("><", list->str[*i]) == 0)
		*i += 1;
	while (list->str[*i] && strchr("><", list->str[*i]))
		*i += 1;
	if (list->str[*i])
	{
		if (check_extra_redir_errthree(temp_list, list->str, *i) == 0)
			return (0);
		return (1);
	}
	else
	{
		if (sorry_i_no_have_name_left(temp_list, list) == 0)
			return (0);
		return (1);
	}
}

int check_extra_redir(t_tok_list *list)
{
	int i;
	int error;
	t_tok_list *temp_list;

	temp_list = list;
	while (list)
	{
		i = 0;
		if (list->child && check_extra_redir(list->child) == 0)
			return (check_extra_redir_errone(temp_list));
		if (list->token == REDIR_TYPE)
		{
			if (check_all_condition(temp_list, list, &i) == 0)
				return (0);
		}
		list = list->next;
	}
	return (1);
}

int check_child_valid(t_tok_list *head)
{
	int is_error;
	t_tok_list *temp;

	if (head == NULL)
		return 0;
	is_error = 0;
	temp = head->child;
	if (temp)
		is_error += check_child_valid(temp);
	if (head)
	{
		if (head->token == 0)
		{
			if (head->str == 0 || head->str[0] == 0)
				is_error++;
		}
		if (head->token == ERROR_TYPE)
			return (1);
	}
	is_error += check_child_valid(head->next);
	return is_error;
}

int	check_error_sticky_child(t_exec *head)
{
	int	i;

	i = 0;
	if (head->child)
		i += check_error_sticky_child(head->child);
	if (head->child && head->next && head->run_condition == 0)
		return (1);
	if (head->next)
		i += check_error_sticky_child(head);
}

int check_child_valid_exec(t_exec *head);

int	child_valid_on_child(t_exec *head)
{
	if (head->child && check_child_valid_exec(head->child) == 0)
	{
		write(2, "minishell : syntax error near unexpected token `", 48);
		if (head->child->cmd && head->child->cmd->s)
			write(2, head->child->cmd->s, strlen(head->child->cmd->s));
		else
			write(2, "(", 1);
		write(2, "`\n", 2);
		return (0);
	}
	return (1);
}

int check_child_valid_exec(t_exec *head)
{
	while (head)
	{
		if (child_valid_on_child(head) == 0)
			return (0);
		if ((head->child && head->cmd) || (head->child && head->next && head->run_condition == 0))
		{
			printf("in errorrr child next no condition\n");
			return (0);
		}
		if (head->child && head->cmd && head->cmd->s)
		{
			write(2, "minishell : syntax error near unexpected token `", 48);
			if (head->child->cmd && head->child->cmd->s)
				write(2, head->child->cmd->s, strlen(head->child->cmd->s));
			else
				write(2, "(", 1);
			write(2, "`\n", 2);
			return (0);
		}
		head = head->next;
	}
	return (1);
}

int	child_and_condition_err(t_tok_list *head)
{
	write(2, "minishell : syntax error near unexpected token `", 48);
	if (head->str && head->str[0])
		write(2, head->str, strlen(head->str));
	else
		write(2, "(", 1);
	write(2, "`\n", 2);
	return (1);
}

int check_child_condition_valid(t_tok_list *head, int lock)
{
	if (head == 0)
		return (0);
	while (head)
	{
		if (head->token == PARENT_TYPE)
		{
			lock++;
			if (head->child && check_child_condition_valid(head->child, 1))
				return (1);
		}
		else if (head->token == CONDITION_TYPE)
			lock = 0;
		if (lock > 2)
			return (child_and_condition_err(head));
		head = head->next;
	}
	return (0);
}

void ft_free_cmd_list(t_list *head)
{
	if (head == NULL)
		return ;
	if (head->next)
	{
		ft_free_cmd_list(head->next);
		head->next = NULL;
	}
	if (head->s)
	{
		free(head->s);
		head->s = NULL;
	}
	free(head);
	head = NULL;
}

void ft_free_redir_list(t_redirect *head)
{
	if (head == NULL)
		return;
	if (head->next)
	{
		ft_free_redir_list(head->next);
		head->next = NULL;
	}
	if (head->front_fd)
	{
		free(head->front_fd);
		head->front_fd = NULL;
	}
	if (head->back_fd)
	{
		free(head->back_fd);
		head->back_fd = NULL;
	}
	if (head->heredoc)
	{
		free(head->heredoc);
		head->heredoc = NULL;
	}
	free(head);
	head = NULL;
}

void ft_free_exec(t_exec *head)
{
	if (head == NULL)
		return;
	if (head->child)
	{
		ft_free_exec(head->child);
		head->child = NULL;
	}
	if (head->next)
	{
		ft_free_exec(head->next);
		head->next = NULL;
	}
	if (head->redir)
	{
		ft_free_redir_list(head->redir);
		head->redir = NULL;
	}
	if (head->cmd)
	{
		ft_free_cmd_list(head->cmd);
		head->cmd = NULL;
	}
	free(head);
	head = NULL;
}

int	check_raw_str(char *str)
{
	if (str == NULL)
		return (0);
	if (check_redir_valid(str) == 0)
		return (0);
	if (check_paren_valid(str) == 0)
		return (0);
	return (1);
}

int	check_token_list(t_tok_list *list)
{
	if (list == NULL)
		return (0);
	if (check_extra_redir(list) == 0)
		return (0);
	if (check_child_valid(list) > 0)
	{
		write(2, "minishell: syntax error unexpected token `()'\n", 46);
		ft_free_tok_list(list);
		list = NULL;
		return (0);
	}
	if (check_condition_valid(list))
	{
		ft_free_tok_list(list);
		list = NULL;
		return (0);
	}
	if (check_child_condition_valid(list, 0))
	{
		ft_free_tok_list(list);
		list = NULL;
		return (0);
	}
	return (1);
}

int	check_addition_exec(t_exec *head)
{
	if (check_redir_valid_exec(head) == 0)
		return (0);
	if (check_child_valid_exec(head) == 0)
		return (0);
	return (1);
}

t_exec *parser(char *raw_data, t_map_list *env, int *status)
{
	char *new;
	t_tok_list *list;
	t_exec *head;

	head = NULL;
	new = manage_string_space(raw_data);
	if (check_raw_str(new) == 0)
		return (NULL);
	list = group_per_exec(new);
	if (check_token_list(list) == 0)
		return (NULL);
	ft_free_tok_list(list);
	return NULL;
	get_exec_data(list, &head);
	ft_free_tok_list(list);
	list = NULL;
	if (get_heredoc(head, env, status))
	{
		*status = 1;
		return (NULL);
	}
	if (check_addition_exec(head) == 0)
		return (NULL);
	return (head);
}

// --------------------- end parser ----------

// -------------------- current working ------
t_map_list *copy_map_list(t_map_list *head)
{
	t_map_list *new_head;
	t_map_list *current;
	t_map_list *new_node;
	t_map_list *tail;

	if (head == NULL)
		return NULL;
	new_head = NULL;
	tail = NULL;
	current = head;
	new_node = NULL;
	int i = 0;
	while (current != NULL)
	{
		new_node = ft_new_mapnode(current->key, current->value);
		if (new_head == NULL)
			new_head = new_node;
		else
			tail->next = new_node;
		tail = new_node;
		current = current->next;
		i++;
	}
	return new_head;
}

// --------------------- execute parser ------

int ft_redir_len(t_redirect *head)
{
	int i;

	i = 0;
	while (head)
	{
		i++;
		head = head->next;
	}
	return (i);
}

void execute_recursive(t_exec *cmd, int *status, t_map_list **env, int child);

int	ft_dup2(int f_redir, int b_redir)
{
	if (dup2(b_redir, f_redir) == -1)
	{
		perror("minishell");
		return (1);
	}
	return (0);
}

//----------- run_redir

void	setup_redir(t_redirect *redir, int *f_redir, int *b_redir)
{
	if (redir->front_fd)
	{
		if (redir->front_fd[0] == '&' && redir->front_fd[1] == 0)
			*f_redir = 3222;
		else
			*f_redir = atoi(redir->front_fd);
	}
	else if (redir->type == O_REDIR || redir->type == APPEN)
	{
		*f_redir = STDOUT_FILENO;
		*b_redir = STDOUT_FILENO;
	}
	else if (redir->type == I_REDIR || redir->type == HERED)
	{
		*f_redir = STDIN_FILENO;
		*b_redir = STDIN_FILENO;
	}
}

void	add_case_ampersand(t_redirect *redir, int *b_redir, char **file_name)
{
	if (redir->back_fd[1] && ft_strnum(redir->back_fd + 1))
	{
		*b_redir = atoi(redir->back_fd + 1);
	}
	else
	{
		*file_name = strdup(redir->back_fd + 1);
	}
}

int	bad_dollar_sign_usage(t_redirect *redir)
{
	if (redir->back_fd[0] == '$' && redir->back_fd[1])
	{
		write(2, "bash: ", 6);
		write(2, redir->back_fd, strlen(redir->back_fd));
		write(2, ": ambiguous redirect\n", 21);
		return (1);
		return (EXIT_FAILURE);
	}
	return (0);
}

void	unquote_and_add_target_fd_ref(t_redirect *redir, int *b_redir, char **file_name)
{
	unquote_realloc_str(&(redir->back_fd));
	if (redir->back_fd[0] == '&')
		add_case_ampersand(redir, b_redir, file_name);
	else
		*file_name = strdup(redir->back_fd);
}

void	getfd_ref_from_next_args(t_exec **data, t_map_list *env, int *status, char **file_name)
{
	*data = (*data)->next;
	replace_str(&(*data)->cmd->s, env, *status);
	unquote_realloc_str(&(*data)->cmd->s);
	*file_name = strdup((*data)->cmd->s);
}

int	run_redir_in(char *file_name, int f_redir)
{
	int fd;
	if (file_name)
	{
		fd = open(file_name, O_RDONLY);
		if (fd == -1)
		{
			write(2, "minishell: ", 11);
			perror(file_name);
			free(file_name);
			return (1);
		}
		free(file_name);
		if (ft_dup2(STDIN_FILENO, fd) == 1)
			return 1;
		close(fd);
	}
	else
	{
		if (ft_dup2(0, f_redir) == 1)
			return (1);
	}
	return (0);
}

int	check_file_avaiable(char *file_name )
{
	if (access(file_name, F_OK) == -1)
	{
		write(2, "minishell: ", 11);
		write(2, file_name, strlen(file_name));
		write(2, ": No such file or directory\n", 29);
		if (file_name)
			free(file_name);
		
		return (1);
	}
	else if (access(file_name, W_OK) == -1)
	{
		write(2, "minishell: ", 11);
		write(2, file_name, strlen(file_name));
		write(2, ": Permission denied\n", 20);
		if (file_name)
			free(file_name);
		return (1);
	}
	return (0);
}

int	run_redir_out_filename(char *file_name, int	b_redir)
{
	int	fd;

	if (file_name)
	{
		if (strchr(file_name, '/') && check_file_avaiable(file_name))
			return (EXIT_FAILURE);
		fd = open(file_name, O_WRONLY | O_CREAT | O_TRUNC, 0666);
		free(file_name);
		if (fd == -1 || ft_dup2(STDOUT_FILENO, fd) == 1)
		{
			if (fd != -1)
				close(fd);
			return (EXIT_FAILURE);
		}
		if (fd == -1 || ft_dup2(STDERR_FILENO, fd) == 1)
		{
			if (fd != -1)
				close(fd);
			return (EXIT_FAILURE);
		}
		close(fd);
		return (0);
	}
	else
	{
		if (ft_dup2(2, b_redir) == 1)
			return 1;
		if (ft_dup2(1, b_redir) == 1)
			return 1;
		return (0);
	}
}

int	run_solo_redir_out(char *file_name, int f_redir, int b_redir)
{
	int	 fd;

	if (file_name)
	{
		if (strchr(file_name, '/'))
		{
			if (check_file_avaiable(file_name) == 1)
				return (1);
		}
		fd = open(file_name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		free(file_name);
		if (fd == -1 || ft_dup2(f_redir, fd) == 1)
		{
			if (fd != -1)
				close(fd);
			return 1;
		}
		close(fd);
		return (0);
	}
	else
	{
		if (ft_dup2(f_redir, b_redir) == 1)
			return 1;
		return (0);
	}
}


int	run_redir_appen(char *file_name, int f_redir)
{
	int	fd;

	if (strchr(file_name, '/') && check_file_avaiable(file_name) == 1)
		return (EXIT_FAILURE);
	fd = open(file_name, O_WRONLY | O_CREAT | O_APPEND, 0644);
	if (f_redir == 3222)
			return (EXIT_FAILURE);
	else
	{
		if (fd == -1 || ft_dup2(f_redir, fd) == 1)
		{
			if (fd != -1)
				close(fd);
			write(2, "minishell: ", 11);
			perror(file_name);
			free(file_name);
			return 1;
		}
		free(file_name);
		// dup2(fd, f_redir);
		close(fd);
	}
	free(file_name);
	return (0);
}

int	run_redir_heredoc(char *file_name, t_redirect *redir)
{
	int pipe_fd[2];
	pipe(pipe_fd);

	if (file_name)
		free(file_name);
	if (fork() == 0)
	{
		close(pipe_fd[0]);
		write(pipe_fd[1], redir->heredoc, strlen(redir->heredoc));
		close(pipe_fd[1]);
		exit(EXIT_SUCCESS);
	}
	else
	{
		close(pipe_fd[1]);
		wait(NULL);
		dup2(pipe_fd[0], STDIN_FILENO);
		close(pipe_fd[0]);
	}
	return (0);
}

int	manage_out_redir(char *file_name, int f_redir, int b_redir)
{
	if (f_redir == 3222)
	{
		if (run_redir_out_filename(file_name, b_redir) == 1)
			return (EXIT_FAILURE);
	}
	else
	{
		if (run_solo_redir_out(file_name, f_redir, b_redir) == 1)
			return (EXIT_FAILURE);
	}
	return (EXIT_SUCCESS);
}

int	start_run_redir(t_redirect **redir, char **file_name, int f_redir, int b_redir)
{
	if ((*redir)->type == I_REDIR)
	{
		if (run_redir_in(*file_name, f_redir) == 1)
			return (EXIT_FAILURE);
	}
	else if ((*redir)->type == O_REDIR)
	{
		if (manage_out_redir(*file_name, f_redir, b_redir) == 1)
			return (EXIT_FAILURE);
	}
	else if ((*redir)->type == APPEN)
	{
		if (run_redir_appen(*file_name,f_redir) == 1)
			return (EXIT_FAILURE);
	}
	else if ((*redir)->type == HERED)
		run_redir_heredoc(*file_name, *redir);
	*file_name = NULL;
	*redir = (*redir)->next;
	return (EXIT_SUCCESS);
}

int	setup_run_redir(char **file_name, t_redirect **redir, t_exec *data)
{
	*redir = NULL;
	*file_name = NULL;
	if (data->redir == NULL)
		return 1;
	else
		*redir = data->redir;
	return (0);
}

int run_redir(t_exec *data, t_map_list *env, int status, int f_redir)
{
	int b_redir;
	char *file_name;
	t_redirect *redir;

	if (setup_run_redir(&file_name, &redir, data) == 1)
		return (0);
	while (redir)
	{
		// ----- debug ---------
		// file_name = NULL;
		// ------ debug ---------
		setup_redir(redir, &f_redir, &b_redir);
		if (redir->back_fd)
		{
			if (bad_dollar_sign_usage(redir) == 1)
				return (EXIT_FAILURE);
			replace_str(&(redir->back_fd), env, status);
			unquote_and_add_target_fd_ref(redir, &b_redir, &file_name);
		}
		else if (data->next && data->next->run_condition == ARGS_TYPE)
			getfd_ref_from_next_args(&data, env, &status, &file_name);
		else
			return (EXIT_FAILURE);
		if (start_run_redir(&redir, &file_name, f_redir, b_redir) == 1)
			return (EXIT_FAILURE);
	}
	return (EXIT_SUCCESS);
}

void	setup_getcmd(size_t *count, t_list **temp, int *i, t_list *cmd)
{
	*i = 0;
	*count = 0;
	while (cmd)
	{
		*count += 1;
		cmd = cmd->next;
	}
	*temp = cmd;
}

void	*get_cmd_arr_free_return(char **res)
{
	if (res)
	{
		ft_free_chrarr(res);
		free(res);
	}
	return (NULL);
}

char **get_cmd_arr(t_list *cmd, t_map_list *env, int status)
{
	char **res;
	size_t count;
	t_list *temp;
	int i;

	setup_getcmd(&count, &temp, &i, cmd);
	res = (char **)calloc(count + 1, sizeof(char *));
	while (cmd)
	{
		replace_str(&cmd->s, env, status);
		if (cmd->s && cmd->s[0])
		{
			res[i] = strdup(cmd->s);
			unquote_realloc_str(&res[i]);
			i++;
		}
		cmd = cmd->next;
	}
	if (res[0] == 0 || res[0][0] == 0)
		return (get_cmd_arr_free_return(res));
	return (res);
}

size_t ft_map_len(t_map_list *env)
{
	size_t count;

	count = 0;
	while (env)
	{
		count++;
		env = env->next;
	}
	return (count);
}

size_t ft_env_len(t_map_list *env)
{
	size_t res;

	res = 0;
	if (env->key)
		res += strlen(env->key);
	res += 1;
	if (env->value)
		res += strlen(env->value);
	res += 1;
	return (res);
}

char **comply_env(t_map_list *env)
{
	char **res;
	size_t size;
	size_t i;
	size_t temp;

	size = ft_map_len(env);
	if (size == 0)
		return (NULL);
	res = (char **)calloc(size + 1, sizeof(char *));
	i = 0;
	while (env)
	{
		temp = ft_env_len(env);
		res[i] = (char *)calloc(temp, 1);
		strlcat(res[i], env->key, temp);
		strlcat(res[i], "=", temp);
		if (env->value)
			strlcat(res[i], env->value, temp);
		i++;
		env = env->next;
	}
	return (res);
}

void ft_free_chrarr(char **arr)
{
	int i;

	i = 0;
	if (arr == NULL)
		return;
	while (arr[i])
	{
		if (arr[i])
			free(arr[i]);
		arr[i] = NULL;
		i++;
	}
	free(arr[i]);
	// free(arr);
	arr = NULL;
}

int get_status(int status);

void	execve_child(char **cmd_path, char **env_temp)
{
	signal(SIGINT,SIG_HOLD);
	signal(SIGQUIT,SIG_HOLD);
	if (execve(cmd_path[0], cmd_path, env_temp) == -1)
	{
		perror("minishell: exec child");
		if(errno == 13)
			exit(126);
	}
	exit(EXIT_FAILURE);
}

void	execve_wait_for_child(pid_t *pid, int *return_status, char **cmd, char **env)
{
	int status;

	waitpid(*pid, &status, 0);
	if (WIFEXITED(status))
		*return_status = get_status(status);
	else if (WIFSIGNALED(status)) {
		if(WTERMSIG(status) == SIGINT)
		{
			printf("^C\n");
			*return_status = 130;
		}	
		else if(WTERMSIG(status) == SIGQUIT)
		{
			printf("^\\Quit: 3\n");
			*return_status = 131;
		}	
	}
	// ft_free_chrarr(cmd);
	// ft_free_chrarr(env);
}

int execve_in_child(int *return_status, char **cmd_path, char **env_temp)
{
	int status;
	pid_t pid;

	signal(SIGINT,SIG_IGN);
	signal(SIGQUIT,SIG_IGN);
	pid = fork();
	if (pid == -1)
	{
		perror("fork\n");
		return EXIT_FAILURE;
	}
	else if (pid == 0)
		execve_child(cmd_path, env_temp);
	else
	{
		execve_wait_for_child(&pid, return_status, cmd_path, env_temp);
		return (*return_status);
	}
}

char *ft_getenv(char *s, t_map_list *env, int status);

//:FIX:-----------------------------------------------------




int	check_absolute_command(char **cmd_path, int *status)
{
	if (access(cmd_path[0], F_OK) == -1)
	{
		write(2, cmd_path[0], strlen(cmd_path[0]));
		write(2, ": No such file or directory\n", 29);
		*status = 127;
		return (127);
	}
	struct stat fileStat;
	if (stat(cmd_path[0], &fileStat) == 0)
	{
		if (S_ISDIR(fileStat.st_mode))
		{
			write(2, cmd_path[0], strlen(cmd_path[0]));
			write(2, ": is a directory\n", 18);
			*status = 126;
			return (126);
		}
	}
	return (0);
}

int	command_not_found_err(char **all_path, char **cmd_path)
{
	ft_free_chrarr(all_path);
	free(all_path);
	all_path = NULL;
	write(2, "minishell: ", 11);
	write(2, cmd_path[0], strlen(cmd_path[0]));
	write(2, ": command not found\n", 20);
	return (127);
}

int	get_cmd_cmp_update_state(char *s1, char *s2, int *state)
{
	if (strcmp(s1, s2) == 0)
	{
		*state = 1;
		return (1);
	}
	return (0);
}

void	close_dir_and_update(DIR **dir_p, struct dirent **entry, int *i)
{
		if (*dir_p)
			closedir(*dir_p);
		*dir_p = NULL;
		*entry = 0;
		*i += 1;
}

int	get_cmd_state(int *found, char **cmd_path, char **all_path, int i)
{
	struct dirent *entry;
	DIR *dir_p;

	while (all_path[i] && *found == 0)
	{
		dir_p = opendir(all_path[i]);
		if (dir_p != NULL)
		{
			entry = readdir(dir_p);
			while (entry != NULL)
			{
				if (get_cmd_cmp_update_state(cmd_path[0], entry->d_name, found) == 1)
					break;
				entry = readdir(dir_p);
			}
		}
		if (*found == 1)
			break;
		close_dir_and_update(&dir_p, &entry, &i);
	}
	if (dir_p != NULL)
		closedir(dir_p);
	return (i);
}

int	try_run_absolute_cmd(char **cmd_path, int *status, char **all_path)
{
	int temp;

	temp = 0;
	temp = check_absolute_command(cmd_path, status);
	if (temp)
	{
		ft_free_chrarr(all_path);
		free(all_path);
		return (1);
	}
	return (0);
}

char *get_full_cmd_path(char *path, char **cmd)
{
	char *res;

	res = calloc(strlen(path) + strlen(*cmd) + 2, 1);
	strcat(res, path);
	strcat(res, "/");
	strcat(res, *cmd);
	free(*cmd);
	*cmd = res;
	return (res);
}

char	**setup_run_normal_cmd(int *found, t_map_list *env)
{
	char *path;
	char **all_path;

	return (all_path);
}

int	make_full_cmd_path(int found, char **all_path, char **cmd_path ,int i)
{
	int	res;

	res = 0;
	if (found == 0)
		return (command_not_found_err(all_path, cmd_path));
	else if (found == 1)
	{
		get_full_cmd_path(all_path[i], &cmd_path[0]);
		ft_free_chrarr(all_path);
		free(all_path);
	}
	return (0);
}

int run_normal_cmd(char **env_temp, int *status, t_map_list *env,
				   char **cmd_path)
{
	char **all_path;
	int found;
	char *res;
	int i;
	char *path;

	found = 0;
	path = ft_getenv("PATH", env, 0);
	all_path = ft_split(path, ':');
	free(path);
	if (strchr(cmd_path[0], '/'))
	{
		if (try_run_absolute_cmd(cmd_path, status, all_path) == 1)
			return (1);
		found = 2;
	}
	else
		i = get_cmd_state(&found, cmd_path, all_path, 0);
	if (make_full_cmd_path(found, all_path, cmd_path, i) != 0)
	{
		*status = 127;
		return (127);
	}
	i = execve_in_child(status, cmd_path, env_temp);
	return (i);
}

void	setup_check_placeholder(int *checker, bool *in_s_quote, bool *in_d_quote)
{
	*in_s_quote = false;
	*in_d_quote = false;
	checker[0] = 0;
	checker[1] = 0;
}

void check_for_placeholder(int *checker, char *str)
{
	bool in_s_quote;
	bool in_d_quote;

	setup_check_placeholder(checker, &in_s_quote, &in_d_quote);
	if (*str == '$')
		checker[0] = 1;
	while (*str)
	{
		if (strchr("\'\"", *str))
		{
			if (*str == '\"' && in_s_quote == false)
				in_d_quote = !in_d_quote;
			else if (*str == '\'' && in_d_quote == false)
				in_s_quote = !in_s_quote;
			if (in_d_quote)
			{
				checker[1] = 1;
				return;
			}
		}
		str++;
	}
}


int	manage_redir(t_exec *data, int *status, t_map_list *env)
{
	if (data->redir)
	{
		*status = run_redir(data, env, *status, 0);
		if (*status != EXIT_SUCCESS)
			return (EXIT_FAILURE);
	}
	return (EXIT_SUCCESS);
}

void	ft_free_chrarr_with_ptr(char **arr)
{
		ft_free_chrarr(arr);
		free(arr);
}

int	no_cmd_to_run(int *checker, int *status, char **cmd)
{
	if (checker[0] && checker[1] == 0)
	{
		*status = 0;
		return (0);
	}
	write(2, "minishell: : command not found\n", 31);
	*status = 127;
	return (127);
}

int	manage_run_cmd(t_exec *data, int *status, t_map_list **env)
{
	char **cmd;
	char **env_temp;
	int checker[2];

	check_for_placeholder(checker, data->cmd->s);
	cmd = get_cmd_arr(data->cmd, *env, *status);
	if (cmd == NULL)
		return (no_cmd_to_run(checker, status, cmd));
	env_temp = comply_env(*env);
	if (check_buildin(data->cmd->s))
		run_buildin_cmd(data, status, env, cmd);
	else
		run_normal_cmd(env_temp, status, *env, cmd);
	if (cmd)
		ft_free_chrarr_with_ptr(cmd);
	if (env_temp)
		ft_free_chrarr_with_ptr(env_temp);
}

int run_cmd(t_exec *data, int *status, t_map_list **env)
{
	if (manage_redir(data, status, *env) == 1)
		return (EXIT_FAILURE);
	if (data->cmd && data->cmd->s)
		manage_run_cmd(data, status, env);
	return (*status);
}

int get_status(int status) { return (status >> 8) & 0xFF; }

void	setup_start_pipe(pid_t *pid, int *pipefd, int *new_status, int *status)
{
	new_status[0] = *status;
	new_status[1] = *status;
	pipe(pipefd);
	signal(SIGINT,SIG_IGN);
	signal(SIGQUIT,SIG_IGN);
	pid[0] = fork();
	signal(SIGINT,SIG_HOLD);
	signal(SIGQUIT,SIG_HOLD);
}

void	manage_first_pipe_child(int *pipefd, t_exec *data, int *new_status, t_map_list **env)
{
		close(pipefd[0]);
		dup2(pipefd[1], STDOUT_FILENO);
		close(pipefd[1]);
		exit(run_cmd(data, &new_status[0], env));
		// run_cmd(data, &new_status[0], env);
		// exit(EXIT_SUCCESS);
}

int manage_parent_waitchild(int *status, int *pid, int *pipefd)
{
	int paren_status;

	signal(SIGINT,SIG_IGN);
	signal(SIGQUIT,SIG_IGN);
	close(pipefd[0]);
	waitpid(pid[0], NULL, 0);
	waitpid(pid[1], &paren_status, 0);
	mod_sig_handle(sig_handler);
	if (WIFEXITED(paren_status)) {
		*status = get_status(paren_status);
	}
	else if (WIFSIGNALED(paren_status)) 
	{
		if(WTERMSIG(paren_status) == SIGINT)
		{
			printf("^C\n");
			*status = 130;
		}	
		else if(WTERMSIG(paren_status) == SIGQUIT)
		{
			printf("^\\Quit: 3\n");
			*status = 131;
		}	
	}
}

// :FIX:
void start_pipe(t_exec *data, int *status, t_map_list *env , int *std)
{
	int pipefd[2];
	pid_t pid[2];
	t_map_list *temp;
	int new_status[2];

	// temp = copy_map_list(env);
	setup_start_pipe(pid, pipefd, new_status, status);
	if (pid[0] == 0)
		manage_first_pipe_child(pipefd, data, new_status, &env);
		//manage_first_pipe_child(pipefd, data, new_status, &temp);
	else
	{
		close(pipefd[1]);
		pid[1] = fork();
		if (pid[1] == 0)
		{
			if (dup2(pipefd[0], STDIN_FILENO) == -1)
			{
				close(pipefd[0]);
				exit(EXIT_FAILURE);
			}
			close(pipefd[0]);
			execute_recursive(data->next, &new_status[1], &env, 1);
			exit(EXIT_FAILURE);
		}
		else
			manage_parent_waitchild(status, pid, pipefd);
	} // :TODO: check do i need to free t_map_list temp or not;
}

// ----------------------- post parse ---

int	setup_is_parse_able(int *status, bool *in_s_quote, bool *in_d_quote, char *s)
{
	*status = 0;
	*in_s_quote = false;
	*in_d_quote = false;
	if (s[1] && s[1] == '=')
		return (0);
	return (1);
}

int is_parse_able(char *s)
{
	int count;
	int status;
	bool in_s_quote;
	bool in_d_quote;

	if (setup_is_parse_able(&status, &in_s_quote, &in_d_quote, s) == 0)
		return (0);
	while (*s)
	{
		if (*s == '\"' && in_s_quote == false)
			in_d_quote = !in_d_quote;
		else if (*s == '\'' && in_d_quote == false)
			in_s_quote = !in_s_quote;
		else if (*s == '$' && in_s_quote == false)
		{
			if (*s && s[1] && strchr("\'\"", s[1]) == 0)
				status = 1;
		}
		s++;
	}
	if (status)
		return (1);
	return (0);
}

char *i_hope_i_can_use_getpid(void)
{
	int D;

	D = 69;
	if (8 == D)
	{
		printf("thanks for let me use getpid\n");
		return (NULL);
	}
	else
		return (strdup("<SUPPOSE TO BE PID>"));
}

// -----------------itoa start ---------------

char *zero(void)
{
	char *ptr;

	ptr = malloc(2);
	if (ptr == NULL)
		return (ptr);
	ptr[0] = '0';
	ptr[1] = '\0';
	return (ptr);
}

void number_put_in_to_ptr(char **ptr_main, int count, int sum)
{
	char *ptr;

	ptr = *ptr_main;
	if (sum == -2147483648)
	{
		ptr[0] = '-';
		ptr[1] = '2';
		sum = 147483648;
		count++;
	}
	else if (sum < 0)
	{
		sum = -sum;
		ptr[0] = '-';
		count++;
	}
	while (sum > 0)
	{
		count--;
		ptr[count] = (sum % 10) + '0';
		sum = sum / 10;
	}
}

int count_alpha_of_num_in_n(int n)
{
	int count;

	count = 0;
	while (n > 0 || n < 0)
	{
		n = n / 10;
		count++;
	}
	return (count);
}

char *ft_itoa(int n)
{
	int first_n;
	int count;
	char *ptr;

	count = 0;
	first_n = n;
	if (n == 0)
		return (zero());
	if (n < 0)
		n = -n;
	count = count_alpha_of_num_in_n(n);
	if (first_n < 0)
	{
		ptr = malloc(count + 1 + 1);
		if (!ptr)
			return (ptr);
		ptr[count + 1] = '\0';
	}
	else
	{
		ptr = malloc(count + 1);
		ptr[count] = '\0';
	}
	number_put_in_to_ptr(&ptr, count, first_n);
	return (ptr);
}

// ----------------- itoa end --------

char *ft_getenv(char *s, t_map_list *env, int status)
{
	if (strcmp(s, "$") == 0)
		return (i_hope_i_can_use_getpid());
	else if (strcmp(s, "?") == 0)
		return (ft_itoa(status));
	else if (strcmp(s, "0") == 0)
		return (strdup("minishell"));
	while (env)
	{
		if (strcmp(env->key, s) == 0)
			return (strdup(env->value));
		env = env->next;
	}
	return (calloc(1, 1));
}

int ft_strnum_only(char *s)
{
	if (s == NULL || *s == 0)
		return (0);
	while (*s && *s >= '0' && *s <= '9')
		s++;
	if (*s)
		return (0);
	return (1);
}

void	setup_replace_addback(char *str, size_t *index, char **buf, char **ptr)
{
	*index += 1;
	// *buf = calloc(strlen(str + *index + 1), 1);
	*buf = calloc(strlen(str + *index) + 1, 1);
	*ptr = *buf;
}

char *replace_addback_return(char **buf, t_map_list *env, int status)
{
	char *temp;

	temp = ft_getenv(*buf, env, status);
	free(*buf);
	*buf = NULL;
	return (temp);
}

char *replace_addback(char *str, size_t *index, t_map_list *env,
					 int status)
{
	char *buf;
	char *ptr;
	int count;

	count = 0;
	setup_replace_addback(str, index, &buf, &ptr);
	while (str[*index] && strchr("\"\'", str[*index]) == 0 &&
		   ft_is_space(str[*index]) == 0 && strchr("()=", str[*index]) == 0)
	{
		if (str[*index] == '$' && count > 0)
			break;
		count++;
		*ptr++ = str[*index];
		*index += 1;
		if (ptr - buf < 2)
		{
			if (strcmp(buf, "$") == 0 || strcmp(buf, "?") == 0 ||
				ft_strnum_only(buf))
				break;
		}
	}
	if (str[*index] && strchr("\'\"=()", str[*index]))
		*ptr = 0;
	return (replace_addback_return(&buf, env, status));
}

void	loop_add_buffer(char *str, int i, t_list **res)
{
	char *temp;

	temp = strndup(str, i);
	ft_new_list_addback(res, temp);
	free(temp);
	temp = NULL;
}
void	loop_add_replace(t_list **res, char *temp, char **str, size_t *i)
{
	ft_new_list_addback(res, temp);
	free(temp);
	temp = NULL;
	*str = *str + *i;
	*i = 0;

}

t_list	*add_last_buf(char *str, int i, t_list **res)
{
	char *temp;

	if (i)
	{
		temp = strdup(str);
		ft_new_list_addback(res, temp);
		free(temp);
		temp = NULL;
	}
	return (*res);
}

void	setup_get_replaced(t_list **res, size_t *i, bool *in_s_quote, bool *in_d_quote)
{
	*i = 0;
	*res = NULL;
	*in_s_quote = false;
	*in_d_quote = false;
}

t_list *get_replaced(char *str, t_map_list *env, int status)
{
	t_list *res;
	size_t i;
	char *temp;
	bool in_s_quote;
	bool in_d_quote;

	setup_get_replaced(&res, &i, &in_s_quote, &in_d_quote);
	while (str[i])
	{
		if (str[i] == '\'' && in_d_quote == false && i++ > -1)
			in_s_quote = !in_s_quote;
		else if (str[i] == '\"' && in_s_quote == false && i++ > -1)
			in_d_quote = !in_d_quote;
		else if (str[i] == '$' && str[i + 1] && ft_is_space(str[i + 1]) == 0 &&
				 strchr("\"\'=()", str[i + 1]) == 0 && in_s_quote == false)
		{
			loop_add_buffer(str, i, &res);
			temp = replace_addback(str, &i, env, status);
			loop_add_replace(&res, temp, &str, &i);
		}
		else
			i++;
	}
	return (add_last_buf(str, i, &res));
}

char *unquote_string(char *input)
{
	int i;
	int j;
	bool in_double_quote;
	bool in_single_quote;

	in_double_quote = 0;
	in_single_quote = 0;
	if (input == NULL)
		return NULL;
	int len = strlen(input);
	char *output = calloc((len + 1), 1);
	if (output == NULL)
		return NULL;
	for (i = 0, j = 0; i < len; ++i)
	{
		if (input[i] == '\"' && !in_single_quote)
			in_double_quote = !in_double_quote;
		else if (input[i] == '\'' && !in_double_quote)
			in_single_quote = !in_single_quote;
		else
			output[j++] = input[i];
	}
	output[j] = 0;
	return (output);
}

void unquote_realloc_str(char **str)
{
	char *str_temp;

	if (*str && **str && (strchr(*str, '\"') || strchr(*str, '\'')))
	{
		str_temp = unquote_string(*str);
		free(*str);
		*str = str_temp;
	}
	return;
}

void ft_free_list(t_list *head)
{
	if (head == NULL)
		return;
	if (head->next)
	{
		ft_free_list(head->next);
		head->next = NULL;
	}
	if (head->s)
	{
		free(head->s);
		head->s = NULL;
	}
	free(head);
}

void	replace_str_moving_ptr(t_list **temp, size_t *len)
{
	if ((*temp)->s && (*temp)->s[0])
		*len += strlen((*temp)->s);
	(*temp)= (*temp)->next;
}

void	set_temp_head(t_list **head_temp, t_list *head, t_list **temp)
{
	*head_temp = head;
	*temp = head;
}

void replace_str(char **str, t_map_list *env, int status)
{
	t_list *head;
	t_list *head_temp;
	size_t len;
	t_list *temp;
	char *res;

	len = 0;
	if (*str == 0 || **str == 0 || is_parse_able(*str) == 0)
		return;
	head = get_replaced(*str, env, status);
	if (head == NULL)
		return;
	set_temp_head(&head_temp, head, &temp);
	while (temp)
		replace_str_moving_ptr(&temp, &len);
	res = calloc(len + 1, 1);
	while (head)
	{
		if (head->s && head->s[0])
			strcat(res, head->s);
		head = head->next;
	}
	ft_free_list(head_temp);
	free(*str);
	*str = res;
}

void ft_fflush(int *std, int is_dup, int is_close, int is_flush)
{
	if (is_dup)
	{
		dup2(std[0], STDIN_FILENO);
		dup2(std[1], STDOUT_FILENO);
		dup2(std[2], STDERR_FILENO);
	}
	if (is_close)
	{
		close(std[0]);
		close(std[1]);
		close(std[2]);
	}
	if (is_flush)
	{
		write(STDIN_FILENO, "", 0);
		write(STDOUT_FILENO, "", 0);
		write(STDERR_FILENO, "", 0);
	}
}

// --------------------------------------
// :FIX:

void	set_dup_fd(int fd_close, int fd_open, int f_redir)
{
	close(fd_close);
	dup2(fd_open, f_redir);
	close(fd_open);
}

void ft_free_map_list(t_map_list *env);

int	execute_pipe_parent(t_exec *cmd, pid_t *parent, t_map_list **temp, int *pipefd)
{
	int	child_status;
	int new_status;

	child_status = 0;
	close(pipefd[1]);
	parent[1] = fork();
	if (parent[1] == 0)
	{
		set_dup_fd(pipefd[1], pipefd[0], STDIN_FILENO);
		execute_recursive(cmd->next, &child_status, temp, 1);
		exit(EXIT_FAILURE);
	}
	else
	{
		close(pipefd[0]);
		waitpid(parent[0], NULL, 0);
		waitpid(parent[1], &new_status, 0);
		dup2(STDOUT_FILENO, parent[1]);
		close(pipefd[1]);
		if (cmd->redir)
			run_redir(cmd, *temp, 0, 0);
		ft_free_map_list(*temp);
		free(temp);
		return (get_status(new_status));
	}
}

// ----------------------------------


// ----------------------------------

void	execute_pipe_child(t_exec *cmd, int *status, t_map_list **env)
{
	int new_status;
	pid_t parent[2];
	int pipefd[2];
	int child_status[2];
	t_map_list *temp;

	temp = copy_map_list(*env);
	pipe(pipefd);
	parent[0] = fork();
	if (parent[0] == 0)
	{
		set_dup_fd(pipefd[0], pipefd[1], STDOUT_FILENO);
		execute_recursive(cmd->child, &child_status[0], &temp, 1);
		exit(EXIT_FAILURE);
	}
	else
		*status = execute_pipe_parent(cmd, parent, &temp, pipefd);
}

void	execute_solo_child(t_exec *cmd, t_map_list *env, int *status)
{
	pid_t parent;
	int new_status;
	int	child_status;

	child_status = 0;

	parent = fork();
	if (parent == 0)
	{
		execute_recursive(cmd->child,  &child_status, &env, 1);
		exit(EXIT_FAILURE);
	}
	else
	{
		waitpid(parent, &new_status, 0);
		// *status = child_status;
		if (cmd->redir)
			run_redir(cmd, env, 0, 0);
		if (EXIT_SUCCESS == new_status << 8)
			*status = new_status << 8;
		else
			*status = (((new_status) >> 8) & 0xFF);
	}
}

void	execute_next_cmd(t_exec *cmd, int *status, t_map_list **env, int *std)
{
	if (cmd->run_condition == PIPE && cmd->child == NULL)
	{
		ft_fflush(std, 0, 1, 0);
		start_pipe(cmd, status, *env, std);
	}
	else
	{
		ft_fflush(std, 1, 1, 1);
		if (cmd->run_condition == OP_OR)
		{
			if (cmd->child && *status != EXIT_SUCCESS)
				execute_recursive(cmd->next, status, env, 0);
			else if (run_cmd(cmd, status, env) != EXIT_SUCCESS)
				execute_recursive(cmd->next, status, env, 0);
		}
		else if (cmd->run_condition == OP_AND)
		{
			if (cmd->child && *status == EXIT_SUCCESS)
				execute_recursive(cmd->next, status, env, 0);
			else if (run_cmd(cmd, status, env) == EXIT_SUCCESS)
				execute_recursive(cmd->next, status, env, 0);
		}
	}
}

int	setup_execute(t_exec *cmd, int *std)
{
	if (sigint_in == 1)
		return (1);
	if (cmd == NULL)
		return (1);
	std[0] = dup(STDIN_FILENO);
	std[1] = dup(STDOUT_FILENO);
	std[2] = dup(STDERR_FILENO);
	return (0);
}

		// printf("%d, %d, %d, %s\n", cmd->child ? 1 : 0, cmd->next ? 1 : 0, cmd->run_condition, cmd->cmd ? cmd->cmd->s ? cmd->cmd->s : 0 : 0);
	// ---- test ----
	// exec_test(cmd);
	// return ;
	// ----------- end test

void execute_recursive(t_exec *cmd, int *status, t_map_list **env, int child)
{
	pid_t parent[2];
	int pipefd[2];
	t_map_list *temp[2];
	int std[3];

	// ---- test ----
	// exec_test(cmd);
	return ;
	// ----------- end test
	if (setup_execute(cmd, std) == 1)
		return ;
	if (cmd->child)
	{
		if (cmd->run_condition == PIPE)
			execute_pipe_child(cmd, status, env);
		else
			execute_solo_child(cmd, *env, status);
	}
	if (cmd->next)
		execute_next_cmd(cmd, status, env, std);
	else if (cmd->redir || cmd->cmd)
	{
		// if (cmd->child != NULL)
		ft_fflush(std, 1, 1, 1);
		run_cmd(cmd, status, env);
	}
	if (child)
	{
		ft_free_map_list(*env);
		exit(*status);
	}
}

// --------------------- parser test----------
void print_all_data(t_exec *head)
{
	if (head->child)
	{
		print_all_data(head->child);
	}
	if (head->cmd)
	{
		while (head->cmd)
		{
			head->cmd = head->cmd->next;
		}
	}
	if (head->redir)
	{
		while (head->redir)
		{
			head->redir = head->redir->next;
		}
	}
	if (head->next)
		print_all_data(head->next);
}

// --------------------- main ----------------

void ft_stack_std(int *arr)
{
	arr[0] = dup(STDIN_FILENO);
	arr[1] = dup(STDOUT_FILENO);
	arr[2] = dup(STDERR_FILENO);
}

int run_line(char *raw_data, t_map_list **env, int *g_status, t_exec **cmd)
{
	int std[3];
	int return_status;

	ft_stack_std(std);
	*cmd = parser(raw_data, *env, g_status);
	if (*cmd == NULL)
	{
		if ( *g_status != 1)
			*g_status = 258;
		ft_fflush(std, 0, 1, 0);
		return (*g_status);
	}
	execute_recursive(*cmd, g_status, env, 0);
	ft_fflush(std, 1, 1, 0);
	return *g_status;
}

// void print_header(t_map_list *env)
// {
// 	printf("\n"
// 		   " \033[34;5m███╗   ███╗██╗███╗   ██╗██╗\033[0m███████╗██╗  "
// 		   "██╗███████╗██╗     ██╗     \n"
// 		   " \033[34;5m████╗ ████║██║████╗  ██║██║\033[0m██╔════╝██║  "
// 		   "██║██╔════╝██║     ██║     \n"
// 		   " \033[34;5m██╔████╔██║██║██╔██╗ "
// 		   "██║██║\033[0m███████╗███████║█████╗  ██║     ██║     \n"
// 		   " \033[34;5m██║╚██╔╝██║██║██║╚██╗██║██║\033["
// 		   "0m╚════██║██╔══██║██╔══╝  ██║     ██║     \n"
// 		   " \033[34;5m██║ ╚═╝ ██║██║██║ ╚████║██║\033[0m███████║██║  "
// 		   "██║███████╗███████╗███████╗\n"
// 		   " \033[34;5m╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═╝\033[0m╚══════╝╚═╝  "
// 		   "╚═╝╚══════╝╚══════╝╚══════╝\n\n");
// 	printf("The default interactive shell is now on path \033[35;6m%s\033[0m.\n"
// 		   "\033[31;5mBad os detected\033[0m, For more details, please visit "
// 		   "\033[0;33mhttps://www.youtube.com/watch?v=Bu8bH2P37kY\033[0m.\n\n",
// 		   getenv("SHELL"));
// }

void ft_free_map_list(t_map_list *env)
{
	if (env == NULL)
		return;
	if (env->next)
		ft_free_map_list(env->next);
	if (env->key)
	{
		free(env->key);
		env->key = NULL;
	}
	if (env->value)
	{
		free(env->value);
		env->value = NULL;
	}
	free(env);
	env = NULL;
}

void	hook_sigint(t_exec **head, t_map_list **env)
{
	if (sigint_in == 2)
	{
		if (*head)
		{
			ft_free_exec(*head);
			*head = NULL;
		}
		if (*env)
		{
			ft_free_map_list(*env);
			*env = NULL;
		}
	}

}
int	hook_eof(char *input)
{
	printf("%sexit\n", PROMPT_MSG);
	free(input);
	input = NULL;
	sigint_in = 2;
	return (1);
}
void	set_add_history(char *input, t_map_list **env, int*g_status, t_exec **head)
{
	add_history(input);
	run_line(input, env, g_status, head);
	if (sigint_in != 2)
		sigint_in = 0;
}

void	clean_unused_cmd(t_exec *head)
{
	head =NULL;
	if (head != NULL)
	{
		ft_free_exec(head);
	}
}

int minishell(t_map_list *env)
{
	int g_status;
	char *input;
	t_exec *head;
	t_control_sig sig;

	head = NULL;
	g_status = 0;
	while (sigint_in != 2)
	{
		mod_sig_handle(sig_handler);
		input = readline(PROMPT_MSG);
		child_ignore();
		if (!input && hook_eof(input))
			break;
		else if (*input == '\n')
			printf("\n");
		else if (input)
			set_add_history(input, &env, &g_status, &head);
		// clean_unused_cmd(head);
		if (head != NULL)
			ft_free_exec(head);
		head = NULL;
		input = NULL;
	}
	hook_sigint(&head, &env);
	return ((unsigned char)g_status);
}

void setup(t_map_list *env)
{
	char *temp[6];
	char *args[3];
	int new;
	char *shlvl;
	char *lvl;

	sigint_in = 0;
	install_term();
	lvl = ft_itoa(atoi(getenv("SHLVL")) + 1);
	shlvl = calloc(strlen(lvl) + 7, 1);
	strcat(shlvl, "SHLVL=");
	strcat(shlvl, lvl);
	new = 0;
	temp[0] = "export";
	temp[1] = shlvl;
	temp[2] = "CLICOLOR=1";
	temp[3] = "LSCOLORS=ExFxCxDxBxegedabagacad";
	temp[4] = "GREP_OPTIONS=--color=auto";
	temp[5] = NULL;
	buildin_export(env, temp, 0, 0);
	free(lvl);
	free(shlvl);
}


int main(int ac, char *av[], char *envp[])
{
	t_map_list *env;

	env = get_env_list(envp);
	setup(env);
	return (minishell(env));
}
