# Inofficial Rust Implementation of the Threema Protocols

## work in progress.
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
 - [x] blob API
  - [ ] streaming support to reduce memory and provide progress


## Usage
When ready, this will be a rust library crate and API doc will be there.
At the time, it's a bunch of experimental binaries.

## License
As I heavily looked into [Threema for Android](https://github.com/threema-ch/threema-android/), this protocol port is licensed under the [GNU Affero General Public License v3](LICENSE.md) aswell.


    Threema Protocol Library
    Copyright (C) 2021 thejonny

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
