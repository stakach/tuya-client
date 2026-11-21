# Tuya Client

A Crystal shard for discovering and controlling Tuya devices over the local network. It supports LAN protocol versions **3.1, 3.2, 3.3, 3.4 and 3.5**, including session-key negotiation for 3.4 and 3.5.

## Installation

Requires Crystal 1.22 or newer and OpenSSL with AES support.

```yaml
dependencies:
  tuya_client:
    github: stakach/tuya-client
```

Run `shards install`.

## Usage

Pass the device IP address, device ID, local key, and LAN protocol version. The local key is the 16-byte value issued when the device is paired.

```crystal
require "tuya_client"

device = Tuya::Client.new("192.0.2.10", ENV["TUYA_DEVICE_ID"], ENV["TUYA_LOCAL_KEY"],
  version: "3.5")

begin
  pp device.status                      # Hash(String, JSON::Any)
  puts device.on?                       # Bool from datapoint 1
  device.on = true
  device[2] = 70
  device.write({1 => false, 2 => 30})   # One command for both values
ensure
  device.close
end
```

Datapoint IDs and value types depend on the device. Set `on_datapoint:` to use a switch datapoint other than 1. For `device22` firmware, use `query_datapoints: [1, 5]` to request specific IDs. Protocol 3.2 uses this query format with ID 1 by default.

The client opens a TCP connection on the first command and reuses it until `close` or a connection failure. Use `ping` for a heartbeat. Use `receive_update` to wait for a device report and `refresh([18, 19, 20])` to request a report for selected datapoints. Calls on the same client are serialized. Writes can raise `Tuya::DeviceError` with the device return code or `Tuya::ConnectionError` if the connection fails. A write is sent once, so a failure while awaiting the acknowledgement leaves its outcome uncertain.

## Discovery

```crystal
Tuya::Discovery.scan(5.seconds).each do |device|
  puts "#{device.id} #{device.ip} #{device.version}"
end
```

Discovery listens on UDP ports 6666, 6667, and 7000. To solicit announcements from newer 3.5 devices, pass your computer's LAN IPv4 address using `local_ip:`. You can set `broadcast_address:` to your subnet's broadcast address. Create a client from a discovery result with `device.client(local_key)`.

## Development

```sh
shards install
shards build ameba
crystal tool format --check
bin/ameba
crystal spec
```

Protocol references include [homebridge-tuya](https://github.com/iRayanKhan/homebridge-tuya) and [TinyTuya's protocol notes](https://github.com/jasonacox/tinytuya/blob/master/PROTOCOL.md).
