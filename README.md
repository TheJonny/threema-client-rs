# Inofficial Rust Implementation of the Threema Protocols

As I heavily looked into [Threema for Android](https://github.com/threema-ch/threema-android/), this protocol port is licensed under the GNU Affero General Public License v3 aswell.

work in progress.
 - [ ] split main to library and example(s)
 - [ ] account import
   - [x] threema safe
   - [x] id backup
   - [ ] convert standalone binaries to library
 - [x] basic threema transport
   - [x] login
   - [x] receive/send frames
   - [x] decode/encode boxed messages
 - [ ] connection agent
   - [ ] reconnect when connection dies
   - [ ] keep alive echos
   - [ ] receive event stream
   - [ ] send messages
     - [ ] process ack
	 - [ ] keep message while connection is down
 - [ ] directory API
  - [x] lookup public key
  - [ ] ...
  - [ ] registration (POC DONE in python)
 - [ ] blob API
