require "./spec_helper"

describe Tuya::Discovery do
  {
    "3.1" => "000055aa00000001000000130000003d000000007b2267774964223a22706c756731222c226970223a223139322e302e322e32222c2276657273696f6e223a22332e31227dd352510a0000aa55",
    "3.4" => "000055aa00000001000000230000005c000000007d7836c17990433ffeb15fbc99c2e9763ef2d7caf5b46dd03a8d418ba5bf97b23ad9b0e74521eeda470c96c7f9536743cd6b83c81fc7706f5894f568632d8d8b7d3f2ee4eed990c2cb2eb2e2b9764fb9700a48ae0000aa55",
    "3.5" => "00006699000000000001000000230000004d000102030405060708090a0bc73d71459efcdbebab636c95b1c003dbf31256aab341cc9b2bd5c655186e293114ea2d9fe610b7895a010590d1667f544cb75f9c8303c8373dfb3d8ca0885d059100009966",
  }.each do |version, packet|
    it "decodes a #{version} announcement" do
      device = Tuya::Discovery.decode(packet.hexbytes) || fail("Expected a Tuya announcement")
      device.id.should eq("plug#{version[-1]}")
      device.version.to_s.should eq(version)
      device.client("0123456789abcdef", timeout: 1.second).host.should eq(device.ip)
    end
  end

  it "ignores malformed packets" do
    Tuya::Discovery.decode("000055aa00000001000000130000003d".hexbytes).should be_nil
  end
end
