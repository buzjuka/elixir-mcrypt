defmodule Mcrypt.Padder do
  @block_sizes %{
    :cast_128=>8,
    :gost=>8,
    :rijndael_128=>16,
    :twofish=>16,
    :arcfour=>1,
    :cast_256=>16,
    :loki97=>16,
    :rijndael_192=>24,
    :saferplus=>16,
    :wake=>1,
    :blowfish_compat=>8,
    :des=>8,
    :rijndael_256=>32,
    :serpent=>16,
    :xtea=>8,
    :blowfish=>8,
    :enigma=>1,
    :rc2=>8,
    :tripledes=>8 }

  @padding 0
  def zero_pad(text, algorithm) do
    block_size = @block_sizes[algorithm]
    str_len = byte_size(text)

    padding_size = if rem(str_len, block_size) == 0 do
      0
    else
      block_size - rem(str_len, block_size)
    end

    padded_text = String.ljust(text, str_len + padding_size, @padding)
    padded_text
  end
end
