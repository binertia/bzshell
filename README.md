# bzshell

A simple shell implemented in C, following the C99 standard.

## Features
- **Written in C99**: Following the C99 rules.
- **Custom Shell**: Provides basic shell functionality with support for reading input.
- **Concurent Work Support**: Pipe, and, or idea is inherit on command
- **Readline Support**: Uses the `readline` library for input handling (for keep command history in session).

## Library Dependency

- [readline](https://tiswww.case.edu/php/chet/readline/rltop.html)

Make sure to install the `readline` library before compiling.

## Installation

To compile and link the program with the `readline` library, use the following command:

```bash
cc bzshell.c -I/{..path/to..}/readline/include -lreadline -L/{..path/to..}/readline/lib -o {..give bin file a name..} -Wall -Wextra
