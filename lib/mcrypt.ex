defmodule Mcrypt do
  @moduledoc """
  This is a thin wrapper around [`libmcrypt`](http://linux.die.net/man/3/mcrypt).

  Please see the linked man page for details on the available ciphers and modes.
  """

  @on_load :init

  def init do
    path = :filename.join(:code.priv_dir(:mcrypt), 'lib_mcrypt')
    :ok  = :erlang.load_nif(path, 1)
  end

  @type algorithm :: :arcfour | :blowfish | :blowfish_compat | :cast_128 |
  :cast_256 | :des | :enigma | :gost | :loki97 | :rc2 | :rijndael_128 |
  :rijndael_192 | :rijndael_256 | :saferplus | :serpent | :tripledes |
  :twofish | :wake | :xtea
  @type mode :: :ecb | :cbc | :cfb | :ofb | :nofb | :ncfb | :ctr | :stream


  @spec block_encrypt(binary, algorithm, mode, binary, binary) :: {:ok, binary} | :error
  def block_encrypt(plaintext, algorithm, mode, key, iv) do
    padded_plaintext = Mcrypt.Padder.zero_pad(plaintext, algorithm)
    encrypt(padded_plaintext, algorithm, mode, key, iv)
  end

  @spec block_decrypt(binary, algorithm, mode, binary, binary) :: {:ok, binary} | :error
  def block_decrypt(ciphertext, algorithm, mode, key, iv) do
    {:ok, padded_binary} = decrypt(ciphertext, algorithm, mode, key, iv)
    padded_charlist = :erlang.binary_to_list(padded_binary)
    Enum.reverse(padded_charlist) |> Enum.drop_while(fn(x)-> x == 0 end) |> Enum.reverse
  end

  @doc """
  Wraps libmcrypt's `mcrypt_generic`, including setup and teardown of the cipher
  module.
  """
  @spec encrypt(binary, algorithm, mode, binary, binary) :: {:ok, binary} | :error
  def encrypt(_plaintext, _algorithm, _mode, _key, _iv) do
    :erlang.nif_error("nif not loaded")
  end

  @doc """
  Like `encrypt`, but raises on error.
  """
  @spec encrypt!(binary, algorithm, mode, binary, binary) :: binary | no_return
  def encrypt!(plaintext, algorithm, mode, key, iv) do
    case encrypt(plaintext, algorithm, mode, key, iv) do
      {:ok, ciphertext} -> ciphertext
      :error -> raise "Mcrypt error."
    end
  end

  @doc """
  Wraps libmcrypt's `mdecrypt_generic`, including setup and teardown of the
  cipher module.
  """
  @spec decrypt(binary, algorithm, mode, binary, binary) :: {:ok, binary} | :error
  def decrypt(_ciphertext, _algorithm, _mode, _key, _iv) do
    :erlang.nif_error("nif not loaded")
  end

  @doc """
  Like `decrypt`, but raises on error.
  """
  @spec decrypt!(binary, algorithm, mode, binary, binary) :: binary | no_return
  def decrypt!(ciphertext, algorithm, mode, key, iv) do
    case decrypt(ciphertext, algorithm, mode, key, iv) do
      {:ok, plaintext} -> plaintext
      :error -> raise "Mcrypt error."
    end
  end
end
