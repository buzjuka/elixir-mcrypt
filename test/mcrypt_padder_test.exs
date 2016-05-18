defmodule McryptPadderTest do
  use ExUnit.Case

  test "zero pad adds padding if size is less than block size" do
    assert Mcrypt.Padder.zero_pad("aa", :rijndael_256) == "aa" <> String.duplicate("\0", 30)
  end

  test "zero pad doesn't add padding if size is a multiple of block size" do
    ip = String.duplicate("a", 32)
    assert Mcrypt.Padder.zero_pad(ip, :rijndael_256) == ip
  end

  test "zero pad adds padding if size greater than block size" do
    ip = String.duplicate("a", 33)
    assert Mcrypt.Padder.zero_pad(ip, :rijndael_256) == String.duplicate("a", 33) <> String.duplicate("\0", 31)
  end

end

