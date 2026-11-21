require "./spec_helper"

# Wire vectors built independently with Python cryptography, zlib and hmac.
private KEY    = "0123456789abcdef".to_slice
private STATUS = %({"dps":{"1":true}})

describe Tuya::Protocol do
  it "produces a signed 3.1 control packet" do
    protocol = Tuya::Protocol.new(Tuya::Version::V31, KEY)
    io = IO::Memory.new
    protocol.send(io, Tuya::Protocol::Command::Control, STATUS.to_slice)
    expected = "000055aa000000010000000700000047332e3139623362656539343436303436353339776e37675034766b6765597a494e3539787574436c6d5168587a5a62446131724b736a3673567364514c303daff4f06b0000aa55"
    io.to_slice.should eq(expected.hexbytes)
  end

  {
    "3.2" => "000055aa00000014000000080000003b00000000332e32000000000000000000000000c27ee03f8be481e63320de7dc6eb429664215f365b0dad6b2ac8fab15b1d40bd1d52ba370000aa55",
    "3.3" => "000055aa000000140000000a0000002c00000001c27ee03f8be481e63320de7dc6eb429664215f365b0dad6b2ac8fab15b1d40bdd25e287b0000aa55",
    "3.4" => "000055aa000000140000001000000058000000004490b05d74be9368c24a038cbaeded8e41fb8ef70a70a27b93a7e74ffe75426303000aeb4ff51d29188f82e4a162a1f6cf9be14b091c25eb59ff4a0a43f0405ae548049600cc81b2bbf0e928286013ba0000aa55",
    "3.5" => "000066990000000000140000001000000041000102030405060708090a0bfd3fc41d2d5a0e36e826071ac09bb02d00d7578125d73a38555391d1de8991182c62fa938d1a0a10657abf97634d50bc6913e5efad00009966",
  }.each do |version, packet|
    it "decodes a #{version} reply and rejects tampering" do
      protocol = Tuya::Protocol.new(Tuya::Version.parse(version), KEY)
      bytes = packet.hexbytes
      reply = protocol.receive(IO::Memory.new(bytes))
      String.new(reply.payload).should eq(STATUS)
      reply.code.should eq(version == "3.3" ? 1_u32 : 0_u32)

      bytes[25] ^= 1_u8
      expect_raises(Tuya::ProtocolError) { protocol.receive(IO::Memory.new(bytes)) }
    end
  end

  it "rejects an oversized frame before reading the body" do
    bytes = "000055aa000000010000000affffffff".hexbytes
    expect_raises(Tuya::ProtocolError, /length/) do
      Tuya::Frame.read(IO::Memory.new(bytes), Tuya::FrameFormat::CRC, KEY)
    end
  end
end
