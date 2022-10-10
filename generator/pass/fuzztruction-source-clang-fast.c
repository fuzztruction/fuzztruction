/*
This is a wrapper for clang that allows to build targets with our custom compiler
pass.
*/

#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <libgen.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include "debug.h"
#include <assert.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef struct {
    bool is_cxx;
    bool is_64bit;
    bool x_set;
    bool o_set;
} arg_settings_t;

typedef struct {
    char const **argv;
    int argc;
} args_t;

const char* PASS_SO_NAME = "fuzztruction-source-llvm-pass.so";
char *pass_path;

void find_pass()
{
    char *guess;
    char *cwd;

    cwd = getcwd(NULL, 0);
    if (!cwd) {
        PFATAL("Failed to get CWD");
    }

    /* Test if we find it in the cwd  */
    if (asprintf(&guess, "%s/%s", cwd, PASS_SO_NAME) < 0) {
        free(cwd);
        PFATAL("Failed to allocate");
    }
    if (!access(guess, R_OK))
        pass_path = guess;

    free(cwd);

    if (!pass_path) {
        free(pass_path);
        pass_path = NULL;
    } else {
        goto done;
    }

    // FIXME: this path should not be absolute.
    if (asprintf(&guess, "/home/user/fuzztruction/generator/pass/%s", PASS_SO_NAME) < 0) {
        PFATAL("Failed to allocate");
    }
    if (!access(guess, R_OK))
        pass_path = guess;

    done:

    if (!pass_path) {
        free(pass_path);
        FATAL("Failed to find %s\n", PASS_SO_NAME);
    }
}

arg_settings_t* parse_argv(char const *argv[], int argc) {
    arg_settings_t* self = malloc(sizeof(*self));
    if (!self)
        PFATAL("Error during malloc");

    memset(self, 0x00, sizeof(*self));


    char* argv0 = strdup(argv[0]);
    if (!argv0)
        PFATAL("Error durring alloc");

    /* name points into argv0 */
    char* name = basename(argv0);
    if(!strcmp(name, "fuzztruction-source-clang-fast++")) {
        //printf("#fuzztruction-source-clang-fast++ was called\n");
        self->is_cxx = true;
    }
    free(argv0);

    while(argc--) {
        const char* cur = *(argv++);

        if (!strcmp(cur, "-m32"))
            self->is_64bit = false;
        if (!strcmp(cur, "-m64"))
            self->is_64bit = true;
        if (!strcmp(cur, "-x"))
            self->x_set = true;
        if (!strcmp(cur, "-o"))
            self->o_set = true;
    }

    return self;
}

args_t* rewrite_argv(const char *argv[], int argc, arg_settings_t* arg_settings) {
    const int max_args = argc + 64;
    args_t* self = malloc(sizeof(*self));
    self->argc = 0;
    self->argv = malloc(sizeof(*self->argv) * max_args);

    /* Inject/Replace arguments */
    self->argv[self->argc++] = arg_settings->is_cxx ? "clang++" : "clang";
    // Ignore unkown args
    self->argv[self->argc++] = "-Qunused-arguments";

    // Make sure llvm does not use builtins, since we want to
    // replace all calls with out custom instrumented implementations.
    self->argv[self->argc++] = "-fno-builtin-memcpy";
    self->argv[self->argc++] = "-fno-builtin-memmove";
    self->argv[self->argc++] = "-fno-slp-vectorize";
    self->argv[self->argc++] = "-fno-vectorize";

    //self->argv[self->argc++] = "-mno-sse2";
    self->argv[self->argc++] = "-mno-avx";

    // Run our pass
    self->argv[self->argc++] = "-Xclang";
    self->argv[self->argc++] = "-load";
    self->argv[self->argc++] = "-Xclang";
    self->argv[self->argc++] = pass_path;


    /* Process initially passed arguments and potentially drop some of these */
    const char** current = &argv[1];
    while(*current) {
        if (!strcmp(*current, "-Wl,-z,defs") || !strcmp(*current, "-Wl,--no-undefined")) {
            current++;
            continue;
        }

        self->argv[self->argc++] = *current;
        current++;
    }

    // Link against our agent that is called by a call our pass injected into main().
    // FIXME: this path should not be absolute.
    self->argv[self->argc++] = "-L/home/user/fuzztruction/target/debug";
    self->argv[self->argc++] = "-lgenerator_agent";

    // Enable debug output.
    //self->argv[self->argc++] = "-v";
    self->argv[self->argc] = NULL;
    return self;
}

int main(int argc, char const *argv[])
{
    arg_settings_t* arg_settings;
    args_t* new_args;

    if (argc < 2) {
        FATAL("Not enough arguments");
    }

    /*
    Get the path to the runtime object file and the pass library.
    Sets pass_path.
    */
    find_pass();

    /* Parse the flags intended for clang and deduce information we might need */
    arg_settings = parse_argv(argv, argc);

    new_args = rewrite_argv(argv, argc, arg_settings);
    free(arg_settings);

    // printf("rewritten call:\n");
    // printf("#argc=%d\n", new_args->argc);
    // for (int i = 0; i < new_args->argc; i++) {
    //     printf("#[%d]=%s\n", i, new_args->argv[i]);
    // }
    // fflush(NULL);

    execvp(new_args->argv[0], (char**)new_args->argv);

    PFATAL("Failed to execute %s\n", new_args->argv[0]);

    return 0;
}
