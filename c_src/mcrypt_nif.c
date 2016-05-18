#include "erl_nif.h"
#include <mcrypt.h>

static ERL_NIF_TERM encrypt(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 5) {
        return enif_make_badarg(env);
    }

    ErlNifBinary plaintext;
    if (!enif_inspect_binary(env, argv[0], &plaintext)) {
        return enif_make_badarg(env);
    }

    char algorithm[32];
    if (!enif_get_atom(env, argv[1], algorithm, sizeof(algorithm), ERL_NIF_LATIN1)) {
        return enif_make_badarg(env);
    }

    char mode[16];
    if (!enif_get_atom(env, argv[2], mode, sizeof(mode), ERL_NIF_LATIN1)) {
        return enif_make_badarg(env);
    }

    ErlNifBinary key;
    if (!enif_inspect_binary(env, argv[3], &key)) {
        return enif_make_badarg(env);
    }

    ErlNifBinary iv;
    if (!enif_inspect_binary(env, argv[4], &iv)) {
        return enif_make_badarg(env);
    }



    MCRYPT td = mcrypt_module_open(algorithm, NULL, mode, NULL);
    if (td == MCRYPT_FAILED) {
        return enif_make_atom(env, "error");
    }

    int i = mcrypt_generic_init(td, key.data, key.size, iv.data);
    if (i < 0) {
        // const char *err = mcrypt_strerr(i);
        return enif_make_atom(env, "error");
    }

    mcrypt_generic(td, plaintext.data, plaintext.size);

    mcrypt_generic_end(td);

    return enif_make_tuple2(
      env,
      enif_make_atom(env, "ok"),
      enif_make_binary(env, &plaintext)
    );
}

static ERL_NIF_TERM decrypt(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 5) {
        return enif_make_badarg(env);
    }

    ErlNifBinary ciphertext;
    if (!enif_inspect_binary(env, argv[0], &ciphertext)) {
        return enif_make_badarg(env);
    }

    char algorithm[32];
    if (!enif_get_atom(env, argv[1], algorithm, sizeof(algorithm), ERL_NIF_LATIN1)) {
        return enif_make_badarg(env);
    }

    char mode[16];
    if (!enif_get_atom(env, argv[2], mode, sizeof(mode), ERL_NIF_LATIN1)) {
        return enif_make_badarg(env);
    }

    ErlNifBinary key;
    if (!enif_inspect_binary(env, argv[3], &key)) {
        return enif_make_badarg(env);
    }

    ErlNifBinary iv;
    if (!enif_inspect_binary(env, argv[4], &iv)) {
        return enif_make_badarg(env);
    }



    MCRYPT td = mcrypt_module_open(algorithm, NULL, mode, NULL);
    if (td == MCRYPT_FAILED) {
        return enif_make_atom(env, "error");
    }

    int i = mcrypt_generic_init(td, key.data, key.size, iv.data);
    if (i < 0) {
        // const char *err = mcrypt_strerr(i);
        return enif_make_atom(env, "error");
    }

    mdecrypt_generic(td, ciphertext.data, ciphertext.size);

    mcrypt_generic_end(td);

    return enif_make_tuple2(
      env,
      enif_make_atom(env, "ok"),
      enif_make_binary(env, &ciphertext)
    );
}

static ErlNifFunc nif_funcs[] =
{
    {"encrypt", 5, encrypt, 0},
    {"decrypt", 5, decrypt, 0}
};

/* Change Elixir.NIF to the name you use in the project */
ERL_NIF_INIT(Elixir.Mcrypt,nif_funcs,NULL,NULL,NULL,NULL)
