#!/bin/bash
# Regression tests for minishell nested logical/grouped execution fixes

set -e

MSH="./minishell"
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

run_test() {
    local name="$1"
    local input="$2"
    local expected="$3"
    local expected_status="${4:-0}"

    # Run minishell with input, extract output after first prompt, remove trailing prompts
    local output
    output=$(printf '%s\nexit\n' "$input" | "$MSH" 2>&1 | tail -n +2 | sed '/^minishell-3.2\$ exit$/d' | sed '/^minishell-3.2\$$/d' | sed '$d')

    if [ "$output" = "$expected" ]; then
        echo "PASS: $name"
    else
        echo "FAIL: $name"
        echo "  Input:    $input"
        echo "  Expected: '$expected'"
        echo "  Got:      '$output'"
    fi
}

echo "=== Regression Tests ==="

# Logical operator precedence
run_test "OR then AND short-circuit" \
    "true || echo a && echo b" \
    "b"

run_test "AND then OR short-circuit" \
    "false && echo a || echo b" \
    "b"

run_test "Left-associative OR-AND" \
    "echo a || echo b && echo c" \
    "a
c"

run_test "Left-associative AND-OR" \
    "echo a && echo b || echo c" \
    "a
b"

run_test "Triple OR failure" \
    "false || false || echo third" \
    "third"

run_test "Triple AND success" \
    "true && true && echo third" \
    "third"

# Pipes with logical operators
run_test "Pipe then OR success" \
    "echo a | grep a || echo c" \
    "a"

run_test "Pipe then OR failure" \
    "echo a | grep b || echo c" \
    "c"

run_test "Pipe then AND success" \
    "echo a | grep a && echo c" \
    "a
c"

run_test "Pipe then AND failure" \
    "echo a | grep b && echo c" \
    ""

# Nested subshells with pipes and logicals
run_test "Nested subshell pipe OR" \
    "(echo a && (echo b || echo c)) | grep b" \
    "b"

run_test "Double nested group pipe" \
    "((echo a || echo b) && echo c) | grep c" \
    "c"

run_test "Subshell pipe to subshell OR" \
    "(echo a || echo b) | (grep a || grep b)" \
    "a"

run_test "Deep nested OR" \
    "(false || (false || (echo nested)))" \
    "nested"

run_test "Deep nested AND" \
    "(true && (true && (echo nested)))" \
    "nested"

# Chained pipes
run_test "Triple pipe" \
    "echo a | echo b | echo c" \
    "c"

run_test "Nested pipe in subshell" \
    "echo a | (cat | (cat | cat))" \
    "a"

# Edge cases
run_test "Empty subshell" \
    "()" \
    ""

run_test "Subshell with single command" \
    "(echo hi)" \
    "hi"

run_test "Double parens single command" \
    "((echo hi))" \
    "hi"

echo "=== Done ==="
