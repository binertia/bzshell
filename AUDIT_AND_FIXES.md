# Minishell Audit Report — Compilation, Segfaults, and Logical Operator Precedence

## 1. Compile Fixes

### Missing header
- **File:** `bzshell.c`
- **Fix:** Added `#include <sys/wait.h>` to resolve implicit declarations of `waitpid()` and `wait()`.

### Non-portable `SIG_HOLD`
- **File:** `bzshell.c`
- **Problem:** `SIG_HOLD` is not defined on Linux/glibc. It was used in `execve_child()` and `setup_start_pipe()`.
- **Fix:**
  - Removed the two `signal(SIG*,SIG_HOLD)` calls from `execve_child()`. They were unnecessary because `execve()` replaces the process image; if it fails the child exits immediately anyway.
  - Replaced `SIG_HOLD` with `SIG_IGN` in `setup_start_pipe()`. The intent was to keep signals ignored in the parent during the brief fork/pipe setup window.

### Makefile dependency bug
- **File:** `Makefile`
- **Fix:** Added `$(SRC)` as a prerequisite of the `$(NAME)` target so that editing the source file actually triggers recompilation.

---

## 2. Segfault Fixes

### Crash #1 — `free()` of stack pointer in `execute_pipe_parent()`
- **Location:** `bzshell.c:4369`
- **Root cause:** `execute_pipe_child()` declared `t_map_list *temp` on the stack, then passed `&temp` to `execute_pipe_parent()`. The parent later called `free(temp)`, attempting to free a stack address.
- **Fix:** Removed the erroneous `free(temp)` call. The `t_map_list *` itself is a local variable; only the heap-allocated map list nodes (pointed to by `*temp`) need freeing, which is already done via `ft_free_map_list(*temp)`.

### Crash #2 — Invalid `dup2()` to a PID
- **Location:** `bzshell.c:4364`
- **Root cause:** `dup2(STDOUT_FILENO, parent[1])` was called after `waitpid`. `parent[1]` at that point contains a `pid_t` (the second child's process ID), not a file descriptor. This corrupted an arbitrary fd number and could cause unpredictable fd state.
- **Fix:** Removed the line entirely. It served no valid purpose.

### Crash #3 — Double-close of pipe fd
- **Location:** `bzshell.c:4365`
- **Root cause:** `close(pipefd[1])` was called after both children had already been waited for, but `pipefd[1]` was closed much earlier (before the second fork). This was a harmless no-op in most cases, but it cluttered the failure paths.
- **Fix:** Removed the redundant `close(pipefd[1])`.

### Crash #4 — Uninitialized pointer in `buildin_cd_add_pwd()`
- **Location:** `bzshell.c:1181`
- **Root cause:** `char *hidden_pwd` was used with `strcat()` without ever being allocated.
- **Fix:** Added `hidden_pwd = calloc(strlen(str_temp) + 6, 1);` before writing into it.

### Crash #5 — Uninitialized pointer in `buildin_export()`
- **Location:** `bzshell.c:1450`
- **Root cause:** `char **res` was passed uninitialized to `setup_buildin_export()`.
- **Fix:** Initialized `res` to `NULL`.

---

## 3. Logical Operator Precedence Fix

### Symptom
Chains like `echo a || echo b && echo c` or `false && echo a || echo b` produced wrong output or wrong exit codes.

### Root cause
The executor treated `&&` and `||` with **wrong associativity**. In the flat `t_exec` linked list:

```
exec1 --OP_OR--> exec2 --OP_AND--> exec3
```

`execute_next_cmd()` decided whether to recurse to `cmd->next` based only on the **current** node's condition. When `exec1` succeeded with `OP_OR`, the code simply stopped — it never evaluated `exec2`'s `OP_AND` condition, so `exec3` was never reached.

Bash evaluates `&&` and `||` with **equal precedence, left-associative**:
- `a || b && c`  →  `(a || b) && c`
- `a && b || c`  →  `(a && b) || c`

### Fix
Introduced a **short-circuit skip flag** passed through `execute_recursive()`:

```c
void execute_recursive(t_exec *cmd, int *status, t_map_list **env, int child, int skip);
```

- `skip == 0`: execute the current node normally.
- `skip == 1`: do **not** run the current command, but still **evaluate** the node's logical condition to decide whether the *next* node should run.

`execute_next_cmd()` was simplified to compute `next_skip` based on the current result:

```c
next_skip = (cmd->run_condition == OP_OR)
    ? (*status == EXIT_SUCCESS)   // success → skip next (short-circuit OR)
    : (*status != EXIT_SUCCESS);  // failure → skip next (short-circuit AND)
```

This makes the walker propagate short-circuit decisions correctly through arbitrarily long mixed `&&` / `||` chains.

### Pipe interaction
Pipes (`|`) have higher precedence than `&&`/`||`. The existing recursive pipe execution already consumed entire pipe units inside forked children, so the only change needed was to **not** call `run_cmd()` on a PIPE node in the parent — that had been causing double-execution of the left side (once in the parent, once in `start_pipe`'s child).

---

## 4. Defensive NULL Checks & Ownership

- `execute_recursive()` now checks `setup_execute(cmd, std, child) == 1` (which includes `cmd == NULL`) before any dereference.
- `run_cmd()` already guarded `manage_run_cmd()` with `if (data->cmd && data->cmd->s)`.
- `ft_free_exec()` and `ft_free_tok_list()` both null-out child/next pointers after recursive free, preventing double-free on repeated cleanup calls.
- `execute_pipe_parent()` no longer frees a stack pointer.

---

## 5. Operator Precedence Validation

All of the following now match Bash behavior:

| Expression | Expected | Status |
|---|---|---|
| `true \|\| echo a && echo b` | `b` | PASS |
| `false && echo a \|\| echo b` | `b` | PASS |
| `echo a \|\| echo b && echo c` | `a` + `c` | PASS |
| `echo a && echo b \|\| echo c` | `a` + `b` | PASS |
| `false \|\| false \|\| echo third` | `third` | PASS |
| `true && true && echo third` | `third` | PASS |
| `echo a \| grep a \|\| echo c` | `a` | PASS |
| `echo a \| grep b \|\| echo c` | `c` | PASS |
| `echo a \| grep a && echo c` | `a` + `c` | PASS |
| `echo a \| grep b && echo c` | *(empty)* | PASS |
| `(echo a && (echo b \|\| echo c)) \| grep b` | `b` | PASS |
| `((echo a \|\| echo b) && echo c) \| grep c` | `c` | PASS |
| `echo a \| (cat \| (cat \| cat))` | `a` | PASS |

---

## 6. Regression Tests

A standalone test script `test_regression.sh` has been added. It runs 20 cases covering:
- Short-circuit `&&` / `||`
- Left-associative chaining
- Pipes combined with logical operators
- Nested subshells / groups
- Deep nesting
- Chained pipes
- Edge cases (empty subshell, double parentheses)

Run with:
```bash
./test_regression.sh
```

---

## 7. Architecture Weaknesses & Suggestions

### Current AST design
The parser builds a **flat linked list** of `t_exec` nodes where each node carries `run_condition` describing the operator to the *next* node. This is simple for linear pipelines but has drawbacks:

1. **Pipe sequences and logical chains share the same list type.**
   - A pipe node consumes its `next` node inside a forked child. The parent has no visibility into how many nodes were consumed, making iterative top-down execution harder.
   - *Suggestion:* Group pipe sequences into a single `PIPE_SEQ` node containing an array/list of commands. This would make pipe boundaries explicit and allow the parent walker to treat the entire sequence as one unit.

2. **Redirections on subshells are applied in the parent, not the child.**
   - `execute_solo_child()` and `execute_pipe_parent()` call `run_redir()` *after* `waitpid()`. This means a redirection like `(echo a) > file` runs the subshell *without* the redirection, then applies the redirection to the parent's fds after the child has already exited.
   - *Suggestion:* Apply redirections inside the forked child, right before `execute_recursive()` or `execve()`.

3. **Heavy recursion in `execute_recursive()` and `ft_free_exec()`.**
   - Deeply nested subshells can blow the C stack.
   - *Suggestion:* Convert `ft_free_exec()` to an explicit stack/queue (iterative). For execution, the logical-chain walker is already mostly flat; only subshell children recurse.

4. **Signal handling around forks is fragile.**
   - Multiple places call `signal(SIGINT, SIG_IGN)` directly. Using `sigaction` consistently and restoring the old handler with `sigprocmask` would be more robust.

5. **`start_pipe()` forks the right side and calls `execute_recursive(..., child=1)`, which then frees the AST copy and exits.**
   - This is correct because the child has its own address space, but it means the pipe child cannot return control to a parent loop. Any restructuring to an iterative executor must keep this fork boundary in mind.

6. **Many uninitialized variables and unused parameters exist in non-execution code (builtins, export, cd).**
   - These were not the source of the reported crashes but are latent bugs. Enabling `-Wall -Wextra -Werror` and cleaning them up incrementally is recommended.

---

## 8. Files Modified

- `bzshell.c` — compilation fixes, segfault fixes, logical operator precedence rewrite, NULL safety, uninitialized variable fixes
- `Makefile` — added source file as build prerequisite
- `test_regression.sh` — new regression test suite

---

## 9. Testing Notes

- Compiled and tested with **AddressSanitizer** (`-fsanitize=address`).
- All 20 regression tests pass with both the normal build and the ASan build.
- No ASan errors (heap-use-after-free, bad-free, stack-buffer-overflow) were observed during nested pipeline/logical/group execution.
