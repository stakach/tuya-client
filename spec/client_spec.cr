require "./spec_helper"

private LOCAL_KEY = "0123456789abcdef"

private def with_device(version : String, *, query_datapoints : Array(Int32)? = nil, connections : Int32 = 1,
                        &server_handler : TCPSocket ->) : Tuya::Client
  server = TCPServer.new("127.0.0.1", 0)
  client = Tuya::Client.new("127.0.0.1", "device-id", LOCAL_KEY, version: version,
    port: server.local_address.port, timeout: 1.second, query_datapoints: query_datapoints)
  spawn do
    connections.times do
      server.accept do |socket|
        socket.read_timeout = 1.second
        server_handler.call(socket)
      end
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

  it "reopens a connection after a device closes each completed reply" do
    commands = Channel(UInt32).new(3)
    client = with_device("3.1", connections: 3) do |socket|
      request = Tuya::Frame.read(socket, Tuya::FrameFormat::CRC, LOCAL_KEY.to_slice)
      payload = request.command == 10 ? %({"dps":{"1":false}}).to_slice : Bytes.empty
      legacy_reply(socket, request.command, payload)
      socket.close
      commands.send(request.command)
    end

    begin
      client.on?.should be_false
      commands.receive.should eq(10)
      client.connected?.should be_false
      client.on?.should be_false
      commands.receive.should eq(10)
      client.on = true
      commands.receive.should eq(7)
    ensure
      client.close
    end
  end

  it "retries a read interrupted on an existing connection" do
    count = 0
    client = with_device("3.1", connections: 2) do |socket|
      count += 1
      request = Tuya::Frame.read(socket, Tuya::FrameFormat::CRC, LOCAL_KEY.to_slice)
      legacy_reply(socket, request.command, %({"dps":{"1":false}}).to_slice)
      if count == 1
        Tuya::Frame.read(socket, Tuya::FrameFormat::CRC, LOCAL_KEY.to_slice)
      end
    end

    begin
      client.status["1"].as_bool.should be_false
      client.status["1"].as_bool.should be_false
      count.should eq(2)
    ensure
      client.close
    end
  end

  it "does not resend a write whose acknowledgement was lost" do
    commands = Channel(UInt32).new(3)
    client = with_device("3.1", connections: 2) do |socket|
      key = LOCAL_KEY.to_slice
      request = Tuya::Frame.read(socket, Tuya::FrameFormat::CRC, key)
      commands.send(request.command)
      if request.command == 10
        legacy_reply(socket, request.command, %({"dps":{"1":false}}).to_slice)
        control = Tuya::Frame.read(socket, Tuya::FrameFormat::CRC, key)
        commands.send(control.command)
      else
        legacy_reply(socket, request.command)
      end
    end

    begin
      client.on?.should be_false
      expect_raises(Tuya::ConnectionError) { client.on = true }
      client.ping
      [commands.receive, commands.receive, commands.receive].should eq([10_u32, 7_u32, 9_u32])
    ensure
      client.close
    end
  end

  it "returns a queued update after the device has closed the connection" do
    client = with_device("3.1") do |socket|
      request = Tuya::Frame.read(socket, Tuya::FrameFormat::CRC, LOCAL_KEY.to_slice)
      legacy_reply(socket, 8_u32, %({"dps":{"1":true}}).to_slice)
      legacy_reply(socket, request.command, %({"dps":{"1":false}}).to_slice)
    end

    begin
      client.on?.should be_false
      client.receive_update["1"].as_bool.should be_true
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
