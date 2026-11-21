require "./spec_helper"

private LOCAL_KEY = "0123456789abcdef"

private def with_device(version : String, *, query_datapoints : Array(Int32)? = nil,
                        &server_handler : TCPSocket ->) : Tuya::Client
  server = TCPServer.new("127.0.0.1", 0)
  client = Tuya::Client.new("127.0.0.1", "device-id", LOCAL_KEY, version: version,
    port: server.local_address.port, timeout: 1.second, query_datapoints: query_datapoints)
  spawn do
    server.accept do |socket|
      socket.read_timeout = 1.second
      server_handler.call(socket)
    end
  ensure
    server.close
  end
  client
end

private def legacy_reply(socket : TCPSocket, command : UInt32, data : Bytes = Bytes.empty, *, code = 0_u32)
  body = IO::Memory.new
  body.write_bytes(code, IO::ByteFormat::BigEndian)
  body.write(data)
  packet = Tuya::Frame.new(1_u32, command, body.to_slice).encode(Tuya::FrameFormat::CRC, LOCAL_KEY.to_slice)
  socket.write(packet[0, 10])
  socket.flush
  Fiber.yield
  socket.write(packet[10..])
  socket.flush
end

describe Tuya::Client do
  it "queries and writes a boolean switch, receives updates, and pings" do
    client = with_device("3.1") do |socket|
      key = LOCAL_KEY.to_slice
      query = Tuya::Frame.read(socket, Tuya::FrameFormat::CRC, key)
      legacy_reply(socket, query.command, %({"dps":{"1":false}}).to_slice)

      control = Tuya::Frame.read(socket, Tuya::FrameFormat::CRC, key)
      legacy_reply(socket, 8_u32, %({"dps":{"1":true}}).to_slice)
      legacy_reply(socket, control.command)

      heartbeat = Tuya::Frame.read(socket, Tuya::FrameFormat::CRC, key)
      legacy_reply(socket, heartbeat.command)
    end

    begin
      client.connected?.should be_false
      client.connect
      client.connected?.should be_true
      client.on?.should be_false
      client.on = true
      client.receive_update["1"].as_bool.should be_true
      client.ping
    ensure
      client.close
    end
    client.connected?.should be_false
  end

  it "queries the requested datapoints and handles an empty device22 acknowledgement" do
    client = with_device("3.2", query_datapoints: [1, 5]) do |socket|
      key = LOCAL_KEY.to_slice
      frame = Tuya::Frame.read(socket, Tuya::FrameFormat::CRC, key)
      request = Tuya::Crypto.ecb(frame.payload[15..], key, encrypt: false)

      if frame.command == 13 && JSON.parse(String.new(request))["dps"].to_json == %({"1":null,"5":null})
        legacy_reply(socket, 13_u32)
        body = Tuya::Crypto.ecb(%({"dps":{"1":true,"5":30}}).to_slice, key, encrypt: true)
        legacy_reply(socket, 8_u32, body)
      end
    end

    begin
      client[5].as_i.should eq(30)
    ensure
      client.close
    end
  end

  it "exposes device error codes" do
    client = with_device("3.1") do |socket|
      frame = Tuya::Frame.read(socket, Tuya::FrameFormat::CRC, LOCAL_KEY.to_slice)
      legacy_reply(socket, frame.command, code: 3_u32)
    end
    begin
      expect_raises(Tuya::DeviceError) { client[1] = false }.code.should eq(3)
    ensure
      client.close
    end
  end

  it "clears the connection after an incomplete reply" do
    client = with_device("3.1") do |socket|
      Tuya::Frame.read(socket, Tuya::FrameFormat::CRC, LOCAL_KEY.to_slice)
    end
    begin
      expect_raises(Tuya::ConnectionError) { client.ping }
      client.connected?.should be_false
    ensure
      client.close
    end
  end
end
