# Inofficial Rust Implementation of the Threema Protocols

This will be a library and tools for the Threema Messaging APIs, to make the service compatible with non mobile phone users (e.g. as desktop app, or bridge to Matrix or XMPP).
For account registration, the official mobile app or a license purchased in the Threema Store is needed. Please do not abuse this as a replacement for their paid Threema Gateway service.

## work in progress.
 - [x] split main to library and example(s)
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
   - [x] lookup public key (`identity/<ID>`)
	- [ ]`identity/fetch_bulk`
   - [ ] registration (POC DONE in python)
   - [ ] own account information `identity/fetch_priv`
   - [ ] link email / phone
   - [ ] search contacts
   - [ ] feature masks
   - [ ] revocation
   - [ ] ...
 - [x] blob API
  - [ ] streaming support to reduce memory and provide progress
 - [ ] VOIP signaling:
  It would be nice to bridge arbitrary webrtc offers/responses, to bridge it to any other network that uses webrtc.
 - [ ] publish crate, when usable
 - [ ] publish rustoc
 - [ ] De-tokio-ize the threema protocol transport (make it usable without massive dependencies and from synchronous code)

## Thanks
 - to Roland Schilling and Frieder Steinmetz, who presented a great protocol overview at 33C3 in 2016 ([Recording and Slides](https://fahrplan.events.ccc.de/congress/2016/Fahrplan/events/8062.html)) and did a [Go implementation `o3ma`](https://github.com/o3ma/o3/)
 - to [Threema](https://threema.ch) for releasing their code as [open source](https://github.com/threema-ch) in 2020

## Usage
When ready, this will be a rust library crate `threema_client` and API doc will be there. Also the bunch of experimental binaries can be used.

Currentliy, accounts are saved plaintext json and can be generated with the register/load programs.

Examples / Binaries:
 - creating account JSONs:
   - `register.py` Use a license key to register an identity
   - `load_safe`: Download and decrypt Threema-Safe Backup
   - `load_idbackup`: Decrypt ID-Backup
 - blobs:
   - `getblob` get (and optionally delete) a Blob
   - `putblob` upload a Blob
 - `connect`: frequently changing test program: connect to account and print messages
 - planned: `chatwith`: commandline chat with a single peer / group

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
