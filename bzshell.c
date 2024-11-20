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
		printf("");
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
		printf("");
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

void ft_gettime(t_map_list *env);

void intstall_term()
{
	struct termios term;
	tcgetattr(STDIN_FILENO, &term);
	term.c_lflag &= ~ECHOCTL;
	tcsetattr(STDIN_FILENO, TCSANOW, &term);
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

// ----------------- env manage --------------

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

int ft_is_space(int c)
{
	if ((c >= '\t' && c <= '\r') || c == ' ')
		return (1);
	return (0);
}

// ---------------- make string -----------

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
	if (quote != 0)
	{
		write(2, "minishell : syntax error near unexpected token `", 48);
		write(2, "newline`\n", 9);
		return (NULL);
	}
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

void recursive_token_redir_helper(char **src, char **buf_ptr, int *token)
{
	int count;
	int chr_buf;

	count = 0;
	*token = REDIR_TYPE;
	chr_buf = **src;
	while (**src == chr_buf)
	{
		**buf_ptr = **src;
		*buf_ptr += 1;
		*src += 1;
		count++;
	}
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
		*src += 1;
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
		{
			token = *str;
			str++;
			while (*str && *str != token)
				str++;
			if (*str == 0)
				str--;
		}
		if (count < 0)
			break;
		str++;
	}
	if (count == 0)
		return (1);

	write(2, "minishell : syntax error unexpected token at ", 45);
	write(2, "`", 1);
	if (strchr(str, ')'))
		write(2, ")", 1);
	else
		write(2, "newline", 7);
	write(2, "`\n", 2);
	return (0);
}

void recursive_token(char *src, t_tok_list **branch, int root_call);

void recursive_token_paren_helper(char **src, int *token, t_tok_list **list)
{
	char *buf;
	char *buf_ptr;
	int count;

	*list = ft_new_toklist();
	*token = PARENT_TYPE;
	count = 1;
	*src += 1;
	buf = calloc(strlen(*src) + 1, 1);
	buf_ptr = buf;
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
	recursive_token(buf, list, 0);
}

void add_list_data(char **s, int token, t_tok_list *list)
{
	list->str = *s;
	list->token = token;
}

void recursive_token(char *src, t_tok_list **branch, int root_call)
{
	char *buf;
	char *ptr;
	char *temp;
	int token;

	while (*src && ft_is_space(*src))
		src++;
	if (*src == 0)
		return;
	buf = calloc(strlen(src) + 1, 1);
	*branch = ft_new_toklist();
	token = 0;
	ptr = buf;
	while (*src)
	{
		if (ft_is_space(*src))
			break;
		else if (strchr("\"\'", *src))
			recursive_token_quote_helper(&src, &ptr, &token);
		else if (strchr("<>", *src))
		{
			if (*buf == 0 || ft_strnum(buf))
				recursive_token_redir_helper(&src, &ptr, &token);
			if (strchr("\"\'", *src) == 0)
				break;
			src--;
		}
		else if (strchr("|&", *src))
		{
			if (*buf == 0)
			{
				recursive_token_cond_helper(&src, &ptr, &token);
				if (token)
					break;
				src--;
			}
			else
				break;
		}
		else if (strchr("()", *src))
		{
			if (*src == ')')
				src++;
			else if (*buf == 0)
				recursive_token_paren_helper(&src, &token, &(*branch)->child);
			break;
		}
		else
			*ptr++ = *src;
		src++;
	}
	add_list_data(&buf, token, *branch);
	if (src && *src != 0)
		recursive_token(src, &(*branch)->next, 0);
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
	if (head->child)
	{
		ft_free_tok_list(head->child);
		head->child = NULL;
	}
	if (head->next)
	{
		ft_free_tok_list(head->next);
		head->next = NULL;
	}
	if (head->str)
	{
		free(head->str);
		head->str = NULL;
	}
	free(head);
	head = NULL;
}

// --- recursive head ------
t_tok_list *group_per_exec(char *src)
{
	t_tok_list *tok_head;
	int temp;

	temp = 0;
	tok_head = NULL;
	recursive_token(src, &tok_head, 1);
	free(src);
	src = NULL;
	if (valid_raw_data(tok_head, &temp) != 0)
	{
		ft_free_tok_list(tok_head);
		tok_head = NULL;
		return (0);
	}
	return (tok_head);
}

// ---------------------- finish part seperate -------

// ------------------------------build in -----------------------

int buildin_export(t_map_list *env, char **cmd);

//// ------------cd--------------
char *resolve_path(char *path, t_map_list *env)
{
	char *resolved_path = NULL;
	char *temp[3];
	char cwd[800];
	char *str_temp;

	if (path[0] == '/')
	{
		resolved_path = strdup(path);
		temp[0] = "export";
		str_temp = calloc(strlen(resolved_path) + 5, 1);
		strcat(str_temp, "PWD=");
		strcat(str_temp, resolved_path);
		temp[1] = str_temp;
		temp[2] = NULL;
		buildin_export(env, temp);
		free(str_temp);
		if (getcwd(cwd, sizeof(cwd)) == NULL)
			return (resolved_path);
		str_temp = calloc(strlen(cwd) + 8, 1);
		strcat(str_temp, "OLDPWD=");
		strcat(str_temp, cwd);
		temp[1] = str_temp;
		buildin_export(env, temp);
		free(str_temp);
	}
	else
	{
		if (getcwd(cwd, sizeof(cwd)) == NULL)
		{
			perror("cd: error retrieving current directory: getcwd: cannot "
				   "access parent directories");
			return NULL;
		}
		resolved_path = (char *)calloc(strlen(cwd) + strlen(path) + 2, 1);
		strcpy(resolved_path, cwd);
		strcat(resolved_path, "/");
		strcat(resolved_path, path);
		temp[0] = "export";
		str_temp = (char *)calloc(strlen(resolved_path) + 5, 1);
		strcat(str_temp, "PWD=");
		strcat(str_temp, resolved_path);
		temp[1] = str_temp;
		temp[2] = NULL;
		buildin_export(env, temp);
		free(str_temp);
		str_temp = (char *)calloc(strlen(cwd) + 8, 1);
		strcat(str_temp, "OLDPWD=");
		strcat(str_temp, cwd);
		buildin_export(env, temp);
		free(str_temp);
	}
	return resolved_path;
}

char *ft_getenv(char *s, t_map_list *env, int status);

int buildin_cd(t_exec *data, t_map_list *env)
{
	char *res_path;
	char *temp[3];
	char *str_temp;

	if (data->cmd->next == 0 || data->cmd->next->s == 0 ||
		data->cmd->next->s[0] == 0)
	{
		if (chdir(getenv("HOME")) != 0)
		{
			write(2, "minishell: cd: can't go back to root dir\n", 41);
			return (0);
		}
		temp[0] = "export";
		str_temp = ft_getenv("HOME", env, 0);
		temp[1] = calloc(strlen(str_temp) + 5, 1);
		strcat(temp[1], "PWD=");
		strcat(temp[1], str_temp);
		free(str_temp);
		temp[2] = NULL;
		buildin_export(env, temp);
		char cwd[800];
		if (getcwd(cwd, sizeof(cwd)) == NULL)
		{
			free(temp[1]);
			temp[1] = NULL;
			perror("cd: error retrieving current directory: getcwd: cannot "
				   "access parent directories");
			return 1;
		}
		return (0);
	}
	else if (data->cmd->next && data->cmd->next->s &&
			 data->cmd->next->s[0] == '-' &&
			 data->cmd->next->s[1] == 0) /// changed :HACK:
	{
		str_temp = ft_getenv("OLDPWD", env, 0);
		if (str_temp == 0 || *str_temp == 0)
		{
			free(str_temp);
			write(2, "minishell: cd: OLDPWD not set\n", 30);
			return 1;
		}
		res_path = strdup(str_temp);
		free(str_temp);
	}
	else
		res_path = resolve_path(data->cmd->next->s, env);
	if (res_path == NULL)
		return 0;
	if (chdir(res_path) != 0)
	{
		free(res_path);
		res_path = NULL;
		write(2, "minishell: cd: ", 15);
		perror(data->cmd->next->s);
		// free(res_path);
		return 1;
	}
	free(res_path);
	return 0;
}

//// ------- echo ------------------------------------
int buildin_echo(char **cmd)
{
	int j;
	int no_newline;

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

	if (getcwd(cwd, sizeof(cwd)) == NULL)
	{
		printf("%s\n", getenv("PWD"));
	}
	else
		printf("%s\n", cwd);
	return (0);
}

////
//// -------- export ------------------------------

int char_valid(char c)
{
	if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' ||
		c == '+')
		return (1);
	return (0);
}

int check_export_valid(char *cmd)
{
	size_t i;
	int append;

	append = 0;
	i = 0;
	if (strchr("!@#$%^&*()+=\\-\"'{[]}$?&:;~`.,/*1234567890", cmd[0]))
		return (0);
	while (cmd[i] && cmd[i] != '=')
	{
		if (char_valid(cmd[i]) == 0)
			return (0);
		if (cmd[i] == '+')
		{
			if (cmd[i + 1] && cmd[i + 1] == '=')
				append = 1;
			else
				return (0);
		}
		i++;
	}
	if (i == 0)
		return (0);
	else if (i == 1)
	{
		if (strchr("!@#$%^&*()+=\\-\"'{[]}$?&:;~`.,/*1234567890", cmd[0]))
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

int is_env_dup(t_map_list *env, char **data, int condition)
{
	while (env)
	{
		if (strcmp(env->key, data[0]) == 0)
		{
			if (condition == 1)
			{
				char *new = calloc(strlen(env->value) + strlen(data[1]) + 1, 1);
				strcat(new, env->value);
				strcat(new, data[1]);
				if (env->value)
					free(env->value);
				env->value = new;
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

int buildin_export(t_map_list *env, char **cmd)
{
	char **res;
	size_t temp;
	size_t i;
	size_t j;
	int status;
	t_map_list *env_temp;
	char *cmd_temp;

	env_temp = env;
	status = 0;
	int condition = 0;
	if (cmd[1] == 0)
		print_export(env);
	else
	{
		j = 1;
		while (cmd[j])
		{
			condition = check_export_valid(cmd[j]);
			if (condition)
			{
				if (cmd[j] == NULL && cmd[j] == 0)
					break;
				if (strchr(cmd[j], '=') == NULL)
					break;
				if (condition == 1)
				{
					cmd_temp = cmd[j];
					temp = strchr(cmd_temp, '=') - cmd[j];
					res = (char **)calloc(3, sizeof(char *));
					res[0] = calloc(temp + 1, 1);
					res[1] = calloc((strlen(cmd_temp) - temp) + 1, 1);
					res[2] = NULL;
					i = 0;
					while (*cmd_temp != '=')
						res[0][i++] = *cmd_temp++;
					cmd_temp++;
					i = 0;
					while (*cmd_temp)
						res[1][i++] = *cmd_temp++;
					if (is_env_dup(env, res, 0) == 0)
						ft_add_maplist(&env, res);
					ft_free_chrarr(res);
					free(res);
					res = NULL;
				}
				else if (condition == 2)
				{
					cmd_temp = cmd[j];
					temp = strchr(cmd_temp, '+') - cmd[j];
					res = (char **)calloc(3, sizeof(char *));
					res[0] = calloc(temp + 2, 1);
					res[1] = calloc((strlen(cmd_temp) - temp) + 2, 1);
					res[2] = NULL;
					i = 0;
					while (*cmd_temp != '+')
						res[0][i++] = *cmd_temp++;
					cmd_temp += 2;
					i = 0;
					while (*cmd_temp)
						res[1][i++] = *cmd_temp++;
					// printf("%s == value\n", cmd[1]);
					if (is_env_dup(env, res, 1) == 0)
						ft_add_maplist(&env, res);
					ft_free_chrarr(res);
					free(res);
					res = NULL;
				}
			}
			else
			{
				write(STDERR_FILENO, "minishell: export: ", 19);
				write(STDERR_FILENO, cmd[j], strlen(cmd[j]));
				write(STDERR_FILENO, ": not a valid identifier\n", 25);
				status = 1;
			}
			j++;
		}
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
	if (*env == NULL)
		return;
	if (strcmp((*env)->key, str) == 0)
	{
		// free(env->key);   // comment for testing
		// free(env->value);

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

int handle_over_llong(char *s)
{
	char *llong;

	llong = "9223372036854775808";
	if (*s == '-')
	{
		s++;
		while (*s && *s == '0')
			s++;
		if (strlen(s) < 19)
			return (VALID_LLONG);
		else if (strlen(s) >= 20 || strcmp(s, llong) > 0)
			return (-1);
		else if (strcmp(s, llong) == 0)
			return (0);
	}
	else
	{
		while (*s && *s == '0')
			s++;
		if (strlen(s) >= 20)
			return (-1);
		else if (strlen(s) < 19)
			return (VALID_LLONG);
		if (strcmp(s, llong) >= 0)
			return (-1);
	}
	return (VALID_LLONG);
}

int buildin_exit(char **cmd, int *status)
{
	int size;

	size = 0;
	while (cmd[size])
		size++;
	*status = 0;
	// printf("exit\n");
	if (size == 1)
	{
		sigint_in = 2;
		return (*status);
	}
	else if (size > 2)
	{
		write(2, "minishell: exit: too many arguments\n", 36);
		*status = 1;
		return *status;
	}
	if (handle_over_llong(cmd[1]) != VALID_LLONG)
		*status = handle_over_llong(cmd[1]);
	else if (ft_strnum_exit(cmd[1]))
		*status = ((unsigned char)ft_atoll(cmd[1]));
	else if (cmd[1])
	{
		write(2, "exit: ", 6);
		write(2, cmd[1], strlen(cmd[1]));
		write(2, ": numeric argument required\n", 28);
		*status = 255;
	}
	sigint_in = 2;
	// exit((unsigned char)*status);
	return ((unsigned char)*status);
}

char **get_cmd_arr(t_list *cmd, t_map_list *env, int status);

void run_buildin_cmd(t_exec *data, int *status, t_map_list **env, char **cmd)
{
	if (strcmp("echo", cmd[0]) == 0)
		*status = buildin_echo(cmd);
	if (strcmp("cd", cmd[0]) == 0)
		*status = buildin_cd(data, *env);
	else if (strcmp("pwd", cmd[0]) == 0)
		*status = buildin_pwd(*env);
	else if (strcmp("export", cmd[0]) == 0)
		*status = buildin_export(*env, cmd);
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

	new = malloc(sizeof(t_exec));
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

int get_type_redir(char *s)
{
	int i;
	char temp;

	i = 0;
	while (strchr("><", s[i]) == NULL)
		i++;
	if (s[i] == '>' || s[i] == '<')
	{
		temp = s[i];
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
	}
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
	return (-1);
}

void get_exec_data(t_tok_list *data, t_exec **head)
{
	t_exec *temp;

	if (*head == NULL)
		*head = make_new_exec();
	temp = *head;
	while (data)
	{
		if (data->token == PARENT_TYPE)
		{
			get_exec_data(data->child, &temp->child);
			data = data->next;
		}
		else if (data->token == REDIR_TYPE)
		{
			add_exec_redir(*head, &data);
		}
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
			redir = *str;
			while (*str == redir)
			{
				count++;
				str++;
			}
			if (count > 2)
			{
				write(2, "minishell : syntax error unexpected token at `", 46);
				write(2, &redir, 1);
				write(2, "`\n", 2);
				return (0);
			}
			if (check_child(str) == 0)
			{
				return (0);
			}
			str--;
			count = 0;
		}
		else if (strchr("\'\"", *str))
		{
			token = *str;
			str++;
			while (*str && *str != token)
				str++;
			if (*str == 0)
				str--;
		}
		if (count < 0)
			break;
		str++;
	}
	return (1);
}

// -----------------------------

// ----------------- get heredoc------

void sigint_handler(int signum, siginfo_t *info, void *ptr)
{
	t_pipe *pipe_fds = (t_pipe *)info->si_value.sival_ptr;
	if (signum == SIGINT)
	{
		sigint_in = 1;
		close(pipe_fds->write_fd);
		exit(EXIT_FAILURE);
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

int get_status(int status);

char *add_heredoc(char *eof, int *res_status)
{
	t_pipe pipe_fd;
	char *lines[300];
	char *result;
	int line_count = 0;
	size_t total_length = 0;
	pid_t pid;

	if (pipe((int *)&pipe_fd) == -1)
	{
		perror("Pipe creation failed");
		exit(EXIT_FAILURE);
	}
	pid = fork();

	if (pid < 0)
	{
		perror("Fork failed");
		exit(EXIT_FAILURE);
	}
	else if (pid == 0)
	{
		close(pipe_fd.read_fd);
		sig_setup_heredoc();
		char *input;
		while ((input = readline("heredoc> ")) != NULL)
		{
			if (strcmp(input, eof) == 0 || input == 0)
			{
				free(input);
				break;
			}
			write(pipe_fd.write_fd, input, strlen(input));
			write(pipe_fd.write_fd, "\n", 1);
			free(input);
		}
		write(pipe_fd.write_fd, "\n", 1);
		close(pipe_fd.write_fd);
		exit(EXIT_SUCCESS);
	}
	else
	{
		int status;
		close(pipe_fd.write_fd);
		waitpid(pid, &status, 0);
		sig_ignore();
		if (get_status(status))
		{
			close(pipe_fd.read_fd);
			*res_status = 1;
			return NULL;
		}
		else
			*res_status = 0;

		char buffer[1024];
		ssize_t bytes_read;

		while ((bytes_read = read(pipe_fd.read_fd, buffer, sizeof(buffer))) > 0)
		{
			lines[line_count] = strndup(buffer, bytes_read - 1);
			total_length += strlen(lines[line_count]);
			line_count++;
		}
		close(pipe_fd.read_fd);
		result = (char *)calloc(total_length + line_count, sizeof(char));
		for (int i = 0; i < line_count; i++)
		{
			strcat(result, lines[i]);
			if (i + 1 < line_count)
			{
				strcat(result, "\n");
			}
			free(lines[i]);
		}
		return result;
	}
}

t_list *get_replaced(char *str, t_map_list *env, int status);

int is_parse_able(char *s);

void replace_addback(t_list **head, char *str, size_t *index, t_map_list *env,
					 int status);

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
	while (str[i])
	{
		// printf("change s quote value\n");
		if (str[i] == '\'' && in_d_quote == false)
		{
			in_s_quote = !in_s_quote;
			i++;
		}
		else if (str[i] == '\"' && in_s_quote == false)
		{
			in_d_quote = !in_d_quote;
			i++;
		}
		else if (str[i] == '$' && str[i + 1] && ft_is_space(str[i + 1]) == 0 &&
				 strchr("\"\'=()", str[i + 1]) == 0)
		{
			temp = strndup(str, i);
			ft_new_list_addback(&res, temp);
			free(temp);
			replace_addback(&res, str, &i, env, status);
			str = str + i;
			i = 0;
		}
		else
			i++;
	}
	if (i)
	{
		temp = strdup(str);
		ft_new_list_addback(&res, temp);
		free(temp);
	}
	return (res);
}

void replace_hered_str(char **str, t_map_list *env, int status)
{
	t_list *head;
	size_t len;
	t_list *temp;
	char *res;

	len = 0; /// one line of hell
	if (*str == 0 || **str == 0 || is_parse_able(*str) == 0)
		return;
	head = get_heredoc_replaced(*str, env, status);
	if (head == NULL)
		return;
	temp = head;
	while (temp)
	{
		if (temp->s && temp->s[0])
			len += strlen(temp->s);
		temp = temp->next;
	}
	res = calloc(len + 1, 1);
	// printf("%s", res);
	// strcpy(res, "");
	while (head)
	{
		if (head->s && head->s[0])
			strcat(res, head->s);
		head = head->next;
	}
	free(*str);
	*str = res;
	// *str = res;
}

int get_heredoc(t_exec *head, t_map_list *env, int *status)
{
	t_redirect *temp;
	t_exec *exec_temp;
	char *eof;

	if (head == NULL)
		return 0;
	exec_temp = head;
	while (exec_temp)
	{
		if (head->child)
			get_heredoc(head->child, env, status);
		if (exec_temp->redir)
		{
			temp = exec_temp->redir;
			while (temp)
			{
				if (temp->type == HERED)
				{
					if (temp->back_fd)
						eof = strdup(temp->back_fd);
					else
					{
						if (exec_temp->next == NULL ||
							exec_temp->cmd->s == NULL)
							exit(EXIT_FAILURE);
						else
						{
							eof = strdup(exec_temp->cmd->s);
						}
					}
					temp->heredoc = add_heredoc(eof, status);
					if (*status != 0)
						return 1;
					else
						replace_hered_str(&temp->heredoc, env, *status);
				}
				temp = temp->next;
			}
		}
		exec_temp = exec_temp->next;
	}
	return (0);
}

int check_condition_valid(t_tok_list *list)
{
	int buf;
	buf = 0;
	if (list->child)
	{
		buf = check_condition_valid(list->child);
		if (buf)
			return (1);
	}
	if (list->token == CONDITION_TYPE && list->child == NULL)
	{
		write(2, "minishell : syntax error near unexpected token `", 48);
		if (list->str)
			write(2, list->str, strlen(list->str));
		write(2, "`\n", 2);
		return (1);
	}
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
			{
				write(2, "minishell : syntax error near unexpected token `",
					  48);
				if (list->str)
					write(2, list->str, 1);
				write(2, "`\n", 2);
				return (1);
			}
			if ((list->next && list->next->token == CONDITION_TYPE) ||
				list->next == NULL)
			{
				write(2, "minishell : syntax error near unexpected token `",
					  48);
				if (list->str)
					write(2, list->str, strlen(list->str));
				write(2, "`\n", 2);
				return (1);
			}
		}
		list = list->next;
	}
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
					{
						return (1);
					}
					else
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
				}
				temp = temp->next;
			}
		}
		node = node->next;
	}
	return (1);
}

int check_extra_redir(t_tok_list *list)
{
	int i;
	t_tok_list *temp_list;

	temp_list = list;
	while (list)
	{
		i = 0;
		if (list->child && check_extra_redir(list->child) == 0)
		{
			ft_free_tok_list(temp_list);
			temp_list = NULL;
			return (0);
		}
		if (list->token == REDIR_TYPE)
		{
			while (list->str[i] && strchr("><", list->str[i]) == 0)
				i++;
			while (list->str[i] && strchr("><", list->str[i]))
				i++;
			if (list->str[i])
			{
				if (list->str[i] == '&' && list->str[i + 1] == 0)
				{
					ft_free_tok_list(temp_list);
					temp_list = NULL;
					write(2, "minishell : syntax error near unexpected token `",
						  48);
					write(2, "newline", 7);
					write(2, "`\n", 2);
					return (0);
				}
			}
			else
			{
				if (list->next && list->next->token == ARGS_TYPE)
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
				else
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
			}
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
	{
		is_error += check_child_valid(temp);
	}
	if (head)
	{
		if (head->token == 0)
		{
			if (head->str == 0 || head->str[0] == 0)
				is_error++;
		}
		if (head->token == ERROR_TYPE)
		{
			write(2, "minishell : syntax error unexpected token ` ", 44);
			write(2, "`\n", 2);
			return (1);
		}
	}
	is_error += check_child_valid(head->next);
	return is_error;
}

int check_child_valid_exec(t_exec *head)
{
	while (head)
	{
		if (head->child && check_child_valid_exec(head->child) == 0)
			return (0);
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
		{
			lock = 0;
		}
		if (lock > 2)
		{
			write(2, "minishell : syntax error near unexpected token `", 48);
			if (head->str && head->str[0])
				write(2, head->str, strlen(head->str));
			else
				write(2, "(", 1);
			write(2, "`\n", 2);
			return (1);
		}
		head = head->next;
	}
	return (0);
}

void ft_free_cmd_list(t_list *head)
{
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

t_exec *parser(char *raw_data, t_map_list *env, int *status)
{
	char *new;
	t_tok_list *list;
	t_exec *head;

	head = NULL;
	new = manage_string_space(raw_data);
	if (new == NULL)
		return (NULL);
	if (check_redir_valid(new) == 0)
		return (NULL);
	if (check_paren_valid(new) == 0)
		return (NULL);
	list = group_per_exec(new);
	if (list == NULL)
		return (NULL);
	if (check_extra_redir(list) == 0)
		return (NULL);
	if (check_child_valid(list) > 0)
	{
		ft_free_tok_list(list);
		list = NULL;
		return (NULL);
	}
	if (check_condition_valid(list))
	{
		ft_free_tok_list(list);
		list = NULL;
		return (NULL);
	}
	if (check_child_condition_valid(list, 0))
	{
		ft_free_tok_list(list);
		list = NULL;
		return (NULL);
	}
	get_exec_data(list, &head);
	ft_free_tok_list(list);
	list = NULL;
	if (get_heredoc(head, env, status))
		return (NULL);
	if (check_redir_valid_exec(head) == 0)
		return (NULL);
	if (check_child_valid_exec(head) == 0)
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

	while (current != NULL)
	{
		new_node = ft_new_mapnode(current->key, current->value);
		if (new_head == NULL)
			new_head = new_node;
		else
			tail->next = new_node;
		tail = new_node;
		current = current->next;
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

int run_redir(t_exec *data, t_map_list *env, int status)
{
	int fd;
	int f_redir;
	int b_redir;
	char *file_name;
	t_redirect *redir;

	file_name = NULL;
	redir = data->redir;
	if (redir == NULL)
		return 0;
	while (redir)
	{
		if (redir->front_fd)
		{
			if (redir->front_fd[0] == '&' && redir->front_fd[1] == 0)
				f_redir = 3222;
			else
				f_redir = atoi(redir->front_fd);
		}
		else if (redir->type == O_REDIR || redir->type == APPEN)
		{
			f_redir = 1;
			b_redir = 1;
		}
		else if (redir->type == I_REDIR || redir->type == HERED)
		{
			f_redir = 0;
			b_redir = 0;
		}
		if (redir->back_fd)
		{
			if (redir->back_fd[0] == '$' && redir->back_fd[1])
			{
				write(2, "bash: ", 6);
				write(2, redir->back_fd, strlen(redir->back_fd));
				write(2, ": ambiguous redirect\n", 21);
				return (EXIT_FAILURE);
			}
			replace_str(&(redir->back_fd), env, status);
			unquote_realloc_str(&(redir->back_fd));
			if (redir->back_fd[0] == '&')
			{
				if (redir->back_fd[1] && ft_strnum(redir->back_fd + 1))
				{
					b_redir = atoi(redir->back_fd + 1);
				}
				else
				{
					file_name = strdup(redir->back_fd + 1);
				}
			}
			else
			{
				file_name = strdup(redir->back_fd);
			}
		}
		else if (data->next && data->next->run_condition == ARGS_TYPE)
		{
			data = data->next;
			replace_str(&data->cmd->s, env, status);
			unquote_realloc_str(&data->cmd->s);
			file_name = strdup(data->cmd->s);
		}
		else
		{
			return (EXIT_FAILURE);
		}
		if (redir->type == I_REDIR)
		{
			if (file_name)
			{
				fd = open(file_name, O_RDONLY);
				if (fd == -1)
				{
					write(2, "minishell: ", 11);
					perror(file_name);
					return (1);
				}
				dup2(fd, STDIN_FILENO);
				close(fd);
			}
			else
			{
				if (f_redir == 3222)
					dup2(0, STDIN_FILENO);
				else
					dup2(f_redir, STDIN_FILENO);
			}
		}
		else if (redir->type == O_REDIR)
		{
			if (f_redir == 3222)
			{
				if (file_name)
				{
					if (strchr(file_name, '/'))
					{
						if (access(file_name, F_OK) == -1)
						{
							write(2, "minishell: ", 11);
							write(2, file_name, strlen(file_name));
							write(2, ": No such file or directory\n", 29);
							return (1);
						}
						else if (access(file_name, W_OK) == -1)
						{
							write(2, "minishell: ", 11);
							write(2, file_name, strlen(file_name));
							write(2, ": Permission denied\n", 20);
							return (1);
						}
						else
						{
							fd =
								open(file_name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
							dup2(fd, 2);
							dup2(fd, 1);
							close(fd);
						}
					}
				}
				else
				{
					dup2(1, 2);
					dup2(b_redir, 1);
				}
			}
			else
			{
				if (file_name)
				{
					if (strchr(file_name, '/'))
					{
						if (access(file_name, F_OK) == -1)
						{
							write(2, "minishell: ", 11);
							write(2, file_name, strlen(file_name));
							write(2, ": No such file or directory\n", 29);
							return (1);
						}
						else if (access(file_name, W_OK) == -1)
						{
							write(2, "minishell: ", 11);
							write(2, file_name, strlen(file_name));
							write(2, ": Permission denied\n", 20);
							return (1);
						}
					}
					else
					{
						fd = open(file_name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
						dup2(fd, f_redir);
						close(fd);
					}
				}
				else
					dup2(b_redir, f_redir);
			}
		}
		else if (redir->type == APPEN)
		{
			if (strchr(file_name, '/'))
			{
				if (access(file_name, F_OK) == -1)
				{
					write(2, "minishell: ", 11);
					write(2, file_name, strlen(file_name));
					write(2, ": No such file or directory\n", 29);
					return (1);
				}
				else if (access(file_name, W_OK) == -1)
				{
					write(2, "minishell: ", 11);
					write(2, file_name, strlen(file_name));
					write(2, ": Permission denied\n", 20);
					return (1);
				}
			}
			fd = open(file_name, O_WRONLY | O_CREAT | O_APPEND, 0644);
			if (f_redir == 3222)
			{
				dup2(fd, 2);
				dup2(fd, 1);
				close(fd);
			}
			else
			{
				dup2(fd, f_redir);
				close(fd);
			}
		}
		else if (redir->type == HERED)
		{
			int pipe_fd[2];
			pipe(pipe_fd);

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
		}
		free(file_name);
		file_name = NULL;
		redir = redir->next;
	}
	return (EXIT_SUCCESS);
}

char **get_cmd_arr(t_list *cmd, t_map_list *env, int status)
{
	char **res;
	size_t count;
	t_list *temp;
	int i;

	i = 0;
	count = 0;
	temp = cmd;
	while (temp)
	{
		count++;
		temp = temp->next;
	}
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
	{
		ft_free_chrarr(res);
		free(res);
		return (NULL);
	}
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

int execve_in_child(int *return_status, char **cmd_path, char **env_temp)
{
	pid_t pid;

	pid = fork();
	if (pid == -1)
	{
		perror("fork\n");
		return EXIT_FAILURE;
	}
	else if (pid == 0)
	{
		if (execve(cmd_path[0], cmd_path, env_temp) == -1)
		{
			ft_free_chrarr(cmd_path);
			perror("minishell exec child");
		}
		exit(EXIT_FAILURE);
	}
	else
	{
		int status;
		waitpid(pid, &status, 0);
		*return_status = get_status(status);
		return (*return_status);
	}
}

char *ft_getenv(char *s, t_map_list *env, int status);

int run_normal_cmd(char **env_temp, int *status, t_map_list *env,
				   char **cmd_path)
{
	char *path = ft_getenv("PATH", env, *status);
	char **all_path = ft_split(path, ':');
	free(path);
	int i;
	int found = 0;
	DIR *dir_p;
	struct dirent *entry;

	dir_p = NULL;
	entry = 0;
	i = 0;
	if (strchr(cmd_path[0], '/'))
		found = 2;
	while (all_path[i] && found == 0)
	{
		dir_p = opendir(all_path[i]);
		if (dir_p != NULL)
		{
			entry = readdir(dir_p);
			while (entry != NULL)
			{
				if (strcmp(cmd_path[0], entry->d_name) == 0)
				{
					found = 1;
					break;
				}
				entry = readdir(dir_p);
			}
			// entry = NULL;
		}
		else
		{
			break;
		}
		if (found == 1)
			break;
		entry = 0;
		closedir(dir_p);
		dir_p = NULL;
		i++;
	}
	if (found == 2)
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
	}
	else if (found == 0)
	{
		ft_free_chrarr(all_path);
		free(all_path);
		write(2, "minishell: ", 11);
		write(2, cmd_path[0], strlen(cmd_path[0]));
		write(2, ": command not found\n", 20);
		*status = 127;
		return (127);
	}

	char *res;
	char *ptr;

	if (found == 1)
	{
		res = calloc(strlen(all_path[i]) + strlen(entry->d_name) + 2, 1);
		ptr = res;
		int j = 0;
		while (all_path[i][j])
			*ptr++ = all_path[i][j++];
		*ptr++ = '/';
		j = 0;
		while (entry->d_name[j])
			*ptr++ = entry->d_name[j++];
	}
	ft_free_chrarr(all_path);
	free(all_path);
	if (found == 1)
	{
		free(cmd_path[0]);
		cmd_path[0] = res;
	}
	if (dir_p)
	{
		closedir(dir_p);
		dir_p = NULL;
	}
	i = execve_in_child(status, cmd_path, env_temp);
	return (i);
}

void check_for_placeholder(int *checker, char *str)
{
	bool in_s_quote;
	bool in_d_quote;

	in_s_quote = false;
	in_d_quote = false;
	checker[0] = 0;
	checker[1] = 0;
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

int run_cmd(t_exec *data, int *status, t_map_list **env)
{

	if (data->redir)
	{
		*status = run_redir(data, *env, *status);
		if (*status != EXIT_SUCCESS)
		{
			return (EXIT_FAILURE);
		}
	}
	if (data->cmd && data->cmd->s)
	{
		char **cmd;
		char **env_temp;
		int checker[2];

		check_for_placeholder(checker, data->cmd->s);
		cmd = get_cmd_arr(data->cmd, *env, *status);
		if (cmd == NULL)
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
		env_temp = comply_env(*env);
		if (check_buildin(data->cmd->s))
			run_buildin_cmd(data, status, env, cmd);
		else
			run_normal_cmd(env_temp, status, *env, cmd);
		ft_free_chrarr(cmd);
		ft_free_chrarr(env_temp);
		free(cmd);
		free(env_temp);
	}
	return (*status);
}

int get_status(int status) { return (status >> 8) & 0xFF; }

void start_pipe(t_exec *data, int *status, t_map_list *env)
{
	int pipefd[2];
	pid_t pid[2];
	t_map_list *temp;
	int new_status[2];

	new_status[0] = *status;
	new_status[1] = *status;
	temp = copy_map_list(env);
	pipe(pipefd);
	pid[0] = fork();
	signal(SIGINT, SIG_DFL);
	signal(SIGQUIT, SIG_DFL);
	if (pid[0] == 0)
	{
		close(pipefd[0]);
		dup2(pipefd[1], STDOUT_FILENO);
		close(pipefd[1]);
		run_cmd(data, &new_status[0], &temp);
		exit(EXIT_SUCCESS);
	}
	else
	{
		close(pipefd[1]);
		pid[1] = fork();
		if (pid[1] == 0)
		{
			dup2(pipefd[0], STDIN_FILENO);
			close(pipefd[0]);
			execute_recursive(data->next, &new_status[1], &temp, 1);
		}
		else
		{
			sig_ignore();
			int paren_status;
			close(pipefd[0]);
			waitpid(pid[0], NULL, 0);
			waitpid(pid[1], &paren_status, 0);
			mod_sig_handle(sig_handler);
			*status = get_status(paren_status);
		}
	}
	// free(temp);
}

// ----------------------- post parse ---

int is_parse_able(char *s)
{
	int status;
	bool in_s_quote;
	bool in_d_quote;

	status = 0;
	in_s_quote = false;
	in_d_quote = false;
	if (s[1] && s[1] == '=')
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

void replace_addback(t_list **head, char *str, size_t *index, t_map_list *env,
					 int status)
{
	char *buf;
	char *ptr;
	int count;
	char *temp;

	count = 0;
	*index += 1;
	buf = calloc(strlen(str + *index + 1), 1);
	ptr = buf;
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
	temp = ft_getenv(buf, env, status);
	free(buf);
	ft_new_list_addback(head, temp);
	free(temp);
}

t_list *get_replaced(char *str, t_map_list *env, int status)
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
	while (str[i])
	{
		if (str[i] == '\'' && in_d_quote == false)
		{
			in_s_quote = !in_s_quote;
			i++;
		}
		else if (str[i] == '\"' && in_s_quote == false)
		{
			in_d_quote = !in_d_quote;
			i++;
		}
		else if (str[i] == '$' && str[i + 1] && ft_is_space(str[i + 1]) == 0 &&
				 strchr("\"\'=()", str[i + 1]) == 0 && in_s_quote == false)
		{
			temp = strndup(str, i);
			ft_new_list_addback(&res, temp);
			free(temp);
			replace_addback(&res, str, &i, env, status);
			str = str + i;
			i = 0;
		}
		else
			i++;
	}
	if (i)
	{
		temp = strdup(str);
		ft_new_list_addback(&res, temp);
		free(temp);
	}
	return (res);
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
	head_temp = head;
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
void execute_recursive(t_exec *cmd, int *status, t_map_list **env, int child)
{
	pid_t parent[2];
	int pipefd[2];
	int child_status[2];
	t_map_list *temp1;
	t_map_list *temp2;

	int std[3];

	if (sigint_in == 1)
		return;
	std[0] = dup(STDIN_FILENO);
	std[1] = dup(STDOUT_FILENO);
	std[2] = dup(STDERR_FILENO);

	child_status[0] = 0;
	child_status[1] = 0;
	if (cmd == NULL)
		return;
	if (cmd->child)
	{
		temp1 = copy_map_list(*env);
		temp2 = copy_map_list(*env);
		if (cmd->run_condition == PIPE)
		{
			pipe(pipefd);
			parent[0] = fork();
			if (parent[0] == 0)
			{
				close(pipefd[0]);
				dup2(pipefd[1], STDOUT_FILENO);
				close(pipefd[1]);
				execute_recursive(cmd->child, &child_status[0], &temp1, 1);
				exit(EXIT_FAILURE);
			}
			else
			{
				close(pipefd[1]);
				parent[1] = fork();
				if (parent[1] == 0)
				{
					close(pipefd[1]);
					dup2(pipefd[0], STDIN_FILENO);
					close(pipefd[0]);
					execute_recursive(cmd->next, &child_status[1], &temp2, 1);
					exit(EXIT_FAILURE);
				}
				else
				{
					int new_status;

					close(pipefd[0]);
					if (cmd->redir)
						run_redir(cmd, *env, *status);
					waitpid(parent[0], NULL, 0);
					waitpid(parent[1], &new_status, 0);
					close(pipefd[1]);
					// *status = child_status[1];
					*status = get_status(new_status);
				}
			}
		}
		else
		{
			int new_status;

			parent[0] = fork();
			if (parent[0] == 0)
			{
				execute_recursive(cmd->child, &child_status[0], &temp1, 1);
				exit(EXIT_FAILURE);
			}
			else
			{
				waitpid(parent[0], &new_status, 0);
				*status = child_status[0];
				if (EXIT_SUCCESS == new_status << 8)
					*status = new_status << 8;
				else
					*status = (((new_status) >> 8) & 0xFF);
			}
		}
	}
	if (cmd->next)
	{
		if (cmd->run_condition == PIPE)
		{
			ft_fflush(std, 0, 1, 0);
			start_pipe(cmd, status, *env);
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
	else if (cmd->redir || cmd->cmd)
	{
		ft_fflush(std, 1, 1, 1);
		run_cmd(cmd, status, env);
	}
	if (child)
		exit(*status);
	// free(env);
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

	ft_stack_std(std);
	int return_status = 0;
	*cmd = parser(raw_data, *env, &return_status);
	if (*cmd == NULL)
	{
		ft_fflush(std, 0, 1, 0);
		*g_status = 258;
		return (258);
	}
	execute_recursive(*cmd, g_status, env, 0);
	ft_fflush(std, 1, 1, 0);
	return *g_status;
}

void print_header()
{
	printf("\n"
		   " \033[34;5m███╗   ███╗██╗███╗   ██╗██╗\033[0m███████╗██╗  "
		   "██╗███████╗██╗     ██╗     \n"
		   " \033[34;5m████╗ ████║██║████╗  ██║██║\033[0m██╔════╝██║  "
		   "██║██╔════╝██║     ██║     \n"
		   " \033[34;5m██╔████╔██║██║██╔██╗ "
		   "██║██║\033[0m███████╗███████║█████╗  ██║     ██║     \n"
		   " \033[34;5m██║╚██╔╝██║██║██║╚██╗██║██║\033["
		   "0m╚════██║██╔══██║██╔══╝  ██║     ██║     \n"
		   " \033[34;5m██║ ╚═╝ ██║██║██║ ╚████║██║\033[0m███████║██║  "
		   "██║███████╗███████╗███████╗\n"
		   " \033[34;5m╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═╝\033[0m╚══════╝╚═╝  "
		   "╚═╝╚══════╝╚══════╝╚══════╝\n\n");
	printf("The default interactive shell is now on path \033[35;6m%s\033[0m.\n"
		   "\033[31;5mBad os detected\033[0m, For more details, please visit "
		   "\033[0;33mhttps://www.youtube.com/watch?v=Bu8bH2P37kY\033[0m.\n\n",
		   getenv("SHELL"));
}

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

int minishell(t_map_list *env)
{
	int g_status;
	char *input;
	t_exec *head;

	head = NULL;
	g_status = 0;
	while (sigint_in != 2)
	{
		mod_sig_handle(sig_handler);
		input = readline(PROMPT_MSG);
		child_ignore();
		if (!input)
		{
			printf("%sexit\n", PROMPT_MSG);
			free(input);
			// exit((unsigned char)g_status);
			sigint_in = 2;
			break;
		}
		else if (*input == '\n')
		{
			printf("\n");
			printf("");
		}
		else if (input)
		{
			add_history(input);
			run_line(input, &env, &g_status, &head);
			if (sigint_in != 2)
				sigint_in = 0;
		}
		if (head)
		{
			ft_free_exec(head);
			head = NULL;
		}
		input = NULL;
	}
	if (sigint_in == 2)
	{
		if (head)
		{
			ft_free_exec(head);
			head = NULL;
		}
		if (env)
		{
			ft_free_map_list(env);
			env = NULL;
		}
	}
	return ((unsigned char)g_status);
}

void setup(t_map_list *env)
{
	char *temp[6];
	char *shlvl;
	char *lvl;

	sigint_in = 0;
	install_term();
	lvl = ft_itoa(atoi(getenv("SHLVL")) + 1);
	shlvl = calloc(strlen(lvl) + 7, 1);
	strcat(shlvl, "SHLVL=");
	strcat(shlvl, lvl);
	temp[0] = "export";
	temp[1] = shlvl;
	temp[2] = "CLICOLOR=1";
	temp[3] = "LSCOLORS=ExFxCxDxBxegedabagacad";
	temp[4] = "GREP_OPTIONS=--color=auto";
	temp[5] = NULL;
	buildin_export(env, temp);
	free(lvl);
	free(shlvl);
}

int main(int ac, char *av[], char *envp[])
{
	t_map_list *env;

	print_header();
	env = get_env_list(envp);
	setup(env);
	return (minishell(env));
}
