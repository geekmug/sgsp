#!/usr/bin/env python

__license__ = """
Copyright 2011 Scott A. Dial <scott@scottdial.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from getpass import getpass
from optparse import OptionParser
from struct import pack
from subprocess import Popen, PIPE
import hashlib
import os
import select
import sys
import textwrap

class KeyAssociatedDataDescriptorsList:
    def __len__(self):
        return 0

    def to_buf(self):
        return ''

class SetDataEncryptionPage:
    page_code = 0x0010

    @property
    def page_length(self):
        return len(self)

    def __len__(self):
        return 52 + len(self.key_associated_data_descriptors_list)

    lock = 0
    # 0 = Not locked
    # 1 = The I_T nexus that issued the SECURITY PROTOCOL OUT
    # command is locked to the set of data encryption parameters
    # established at the completion of the processing of the
    # command. (See SSC-3.)

    scope = 1
    # 0 = PUBLIC (All fields other than the scope field and LOCK bit
    # shall be ignored. The I_T nexus shall use data encryption
    # parameters that are shared by other I_T nexuses. If no I_T
    # nexuses are sharing data encryption parameters, the device
    # server shall use default data encryption parameters.)
    # 1 = LOCAL (The data encryption parameters are unique to the I_T
    # nexus associated with the SECURITY PROTOCOL OUT
    # command and shall not be shared with other I_T nexuses.)
    # 2 = ALL I_T NEXUS (The data encryption parameters shall be
    # shared with all I_T nexuses.)

    ckorl = 0
    # 0 = Key is not cleared on reservation loss.
    # 1 = Key is cleared on reservation loss. If the CKORL bit is set to
    # one and there is no reservation in effect for the I_T nexus
    # associated with the SECURITY PROTOCOL OUT command,
    # the device server shall terminate the command with CHECK
    # CONDITION status, with the sense key set to ILLEGAL
    # REQUEST, and the additional sense code set to INVALID
    # FIELD IN PARAMETER DATA.

    ckorp = 0
    # 0 = Key is not cleared on preemption of a persistent reservation.
    # 1 = Key is cleared on preemption of a persistent reservation. If the
    # CKORP bit is set to one and there is no persistent reservation
    # in effect for the I_T nexus associated with the SECURITY
    # PROTOCOL OUT command, the device server shall terminate
    # the command with CHECK CONDITION status, with the sense
    # key set to ILLEGAL REQUEST, and the additional sense code
    # set to INVALID FIELD IN PARAMETER DATA.

    ckod = 0
    # 0 = Key is not cleared on completion of a volume de-mount.
    # 1 = Key is cleared on completion of a volume de-mount. If the
    # CKOD bit is set to one and there is no volume mounted in the
    # device, the device server shall terminate the command with
    # CHECK CONDITION status, with the sense key set to
    # ILLEGAL REQUEST, and the additional sense code set to
    # INVALID FIELD IN PARAMETER DATA.

    sdk = 0
    # 0 = The key is not a supplemental decryption key. If the SDK bit is
    # set to one, the device server shall terminate the command with
    # CHECK CONDITION status, with the sense key set to
    # ILLEGAL REQUEST, and the additional sense code set to
    # INVALID FIELD IN PARAMETER LIST.

    rdmc = 0
    # 0 = Each encrypted block is marked per the default setting for the
    # algorithm.
    # 1 = Reserved
    # 2 = Each encrypted block is marked in a format specific manner
    # as enabled for raw decryption mode operations.
    # 3 = Each encrypted block is marked in a format specific manner
    # as disabled for raw decryption mode operations.

    ceem = 1
    # 0 = Vendor specific.
    # 1 = Encryption mode used when the block was written is not
    # checked.
    # 2 = For READ or VERIFY commands the encryption mode in use
    # when the block was written is checked. Error reported if the
    # block was written in EXTERNAL mode.
    # 3 = For READ or VERIFY commands the encryption mode in use
    # when the block was written is checked. Error reported if the
    # block was written in ENCRYPT mode.

    encryption_mode = 2
    # 0 = DISABLE (Data encryption is disabled.)
    # 1 = EXTERNAL (The data associated with the WRITE(6)
    # command has been encrypted by a system that is compatible
    # with the algorithm specified by the ALGORITHM INDEX field.)
    # 2 = ENCRYPT (The device server shall encrypt all data that it
    # receives for a WRITE(6) command using the algorithm
    # specified in the ALGORITHM INDEX field and the key
    # specified in the KEY field.)

    decryption_mode = 3
    # 0 = DISABLE (Data decryption is disabled. If the device server
    # encounters an encrypted logical block while reading, it shall
    # not allow access to the data.)
    # 1 = RAW (Data decryption is disabled. If the device server
    # encounters an encrypted logical block while reading, it shall
    # pass the encrypted block to the host without decrypting it. The
    # encrypted block may contain data that is not user data.)
    # 2 = DECRYPT (The device server shall decrypt all data that is
    # read from the medium in response to a READ(6) command or
    # verified when processing a VERIFY(6) command. The data
    # shall be decrypted using the algorithm specified in the
    # ALGORITHM INDEX field and the key specified in the KEY
    # field.)
    # 3 = MIXED (The device server shall decrypt all data that is read
    # from the medium that it determines was encrypted in response
    # to a READ(6) command or verified when processing a
    # VERIFY(6) command. The data shall be decrypted using the
    # algorithm specified in the ALGORITHM INDEX field and the
    # key specified in the KEY field. If the device server encounters
    # unencrypted data when processing a READ(6) or VERIFY(6)
    # command, the data shall be processed without decrypting.)

    algorithm_index = 1
    # 01h = AES-256/GCM.
    # If any other value, then the device server shall terminate the
    # command with CHECK CONDITION status, with the sense key set
    # to ILLEGAL REQUEST, and the additional sense code set to
    # INVALID FIELD IN PARAMETER DATA.

    key_format = 0
    # 00h = The KEY field contains the key to be used to encrypt or
    # decrypt data.
    # If any other value, then the device server shall terminate the
    # command with CHECK CONDITION status, with the sense key set
    # to ILLEGAL REQUEST, and the additional sense code set to
    # INVALID FIELD IN PARAMETER DATA.

    @property
    def key_length(self):
        return len(self.key)
    # 32 = Length of key, when included. If any other non-zero value,
    # then the device server shall terminate the command with
    # CHECK CONDITION status, with the sense key set to
    # ILLEGAL REQUEST, and the additional sense code set to
    # INVALID FIELD IN PARAMETER DATA.

    key = (
        '\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff'
        '\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff'
    )

    # If Encryption Mode is EXTERNAL or DISABLE and Decryption
    # Mode is DISABLE or RAW, then this field is not required.
    # If the Key field is missing and either Encryption Mode is ENCRYPT
    # or Decryption Mode is DECRYPT or MIXED, then the device
    # server shall terminate the command with CHECK CONDITION
    # status, with the sense key set to ILLEGAL REQUEST, and the
    # additional sense code set to INVALID FIELD IN PARAMETER
    # DATA.

    key_associated_data_descriptors_list = KeyAssociatedDataDescriptorsList()
    # If the Encryption Mode is ENCRYPT, then this field should contain
    # one descriptor with twelve bytes of authenticated keyassociated
    # data (A-KAD) and one descriptor with sixteen bytes
    # of unauthenticated key-associated data (U-KAD). (See
    # 3.32.2.2 below.) If a descriptor is not included, then the device
    # server shall use a value of all zeroes for the key-associated
    # data that would have been supplied by the missing descriptor.
    # If the Encryption Mode is EXTERNAL, then this field shall contain
    # one metadata key-associated data (M-KAD) descriptor with 64
    # bytes of metadata. If it is not present, then the device server
    # shall terminate the command with CHECK CONDITION status,
    # with the sense key set to ILLEGAL REQUEST, and the
    # additional sense code set to INVALID FIELD IN PARAMETER
    # DATA.
    # If Encryption Mode is DISABLE, then this field must be excluded.
    # If it is present, then the device server shall terminate the
    # command with CHECK CONDITION status, with the sense key
    # set to ILLEGAL REQUEST, and the additional sense code set
    # to INVALID FIELD IN PARAMETER DATA.

    def to_buf(self):
        key = self.key
        if len(key) != 32:
            if (self.encryption_mode == 2
                    or self.decryption_mode == 2
                    or self.decryption_mode == 3):
                raise ValueError('key length must be exactly 32 bytes '
                                 '(was given %d bytes)' % (len(key),))
            key = '\x00' * 32

        data = []
        data.append(pack('>H', self.page_code))
        data.append(pack('>H', self.page_length - 4))
        data.append(pack('>B', ((self.scope & 7) << 5) |
                               ((self.lock & 1) << 0)))
        data.append(pack('>B', ((self.ceem & 3) << 6) |
                               ((self.rdmc & 3) << 4) |
                               ((self.sdk & 1) << 3) |
                               ((self.ckod & 1) << 2) |
                               ((self.ckorp & 1) << 1) |
                               ((self.ckorl & 1) << 0)))
        data.append(pack('>B', self.encryption_mode))
        data.append(pack('>B', self.decryption_mode))
        data.append(pack('>B', self.algorithm_index))
        data.append(pack('>B', self.key_format))
        data.append('\x00' * 8)
        data.append(pack('>H', self.key_length))
        data.append(key)
        data.append(self.key_associated_data_descriptors_list.to_buf())
        return ''.join(data)

class SecurityProtocolOut:
    operation_code = 0xb5
    # The Operation Code for SECURITY PROTOCOL OUT is B5h.

    security_protocol = 0x20
    # 20h = Tape data encryption

    security_protocol_specific = 0x0010
    # 0010h = Set Data Encryption page

    inc_512 = 0
    # Always 0, indicating that the Allocation Length is expressed in
    # bytes.

    @property
    def transfer_length(self):
        return len(self.set_data_encryption_page)
    # Length of data-out in bytes.

    control = 0
    # The control field must be 0.

    set_data_encryption_page = SetDataEncryptionPage()

    def to_buf(self):
        data = []
        data.append(pack('>B', self.operation_code))
        data.append(pack('>B', self.security_protocol))
        data.append(pack('>H', self.security_protocol_specific))
        data.append(pack('>B', ((self.inc_512 & 1) << 7)))
        data.append('\x00')
        data.append(pack('>L', self.transfer_length))
        data.append('\x00')
        data.append(pack('>B', self.control))
        return ''.join(data)

def get_scsi_generic(device):
    lsscsicmd = ['/usr/bin/env', 'lsscsi', '-g']
    p = Popen(lsscsicmd, stdout=PIPE)
    if p.returncode is not None:
        raise EnvironmentError('There was a problem running lsscsi.')

    for line in p.stdout.readlines():
        simple, generic = line.split()[-2:]
        if generic == device or simple == device:
            return generic

    raise EnvironmentError('Unknown device.')

def main():
    parser = OptionParser(usage='usage: %prog [options] [device]')
    parser.add_option('-e', '--enable',
                      action='store_true', dest='enabled', default=True,
                      help='enable encryption/decryption (default)')
    parser.add_option('-d', '--disable',
                      action='store_false', dest='enabled',
                      help='disable encryption/decryption')
    parser.add_option('-v', '--verbose',
                      action='store_true', dest='verbose', default=False,
                      help='be noisy about everything')
    parser.add_option('-p', '--password-from-fd', metavar='FD',
                      dest='password_fd', default=None,
                      help='read password from file descriptor num')
    parser.add_option('-P', '--password-from-file', metavar='FILE',
                      dest='password_file', default=None,
                      help='read password from file')
    parser.add_option('-T', '--twice',
                      action='store_true', dest='twice', default=False,
                      help='ask password twice')
    parser.add_option('-H', '--hash',
                      dest='hash', default='sha256',
                      help='set password hash function (default: %default)')
    parser.add_option('-r', '--raw',
                      dest='raw', default=False,
                      help='disable hashing of password')
    options, args = parser.parse_args()

    if len(args) != 1:
        parser.error('No device specified.')
    if options.password_fd and options.password_file:
        parser.error('Multiple password sources specified.')

    try:
        device = get_scsi_generic(args[0])
    except EnvironmentError, e:
        parser.error(e.message)

    if options.enabled:
        if not options.raw:
            h = hashlib.new(options.hash)

        if options.password_fd is not None or options.password_file is not None:
            if options.password_fd is not None:
                f = os.fdopen(options.password_fd, 'r')
            elif options.password_file is not None:
                f = open(options.password_file, 'rb')

            if not options.raw:
                h = hashlib.new(options.hash)
                h.update(f.read())
                key = h.digest()
            else:
                key = f.read()

            f.close()
        else:
            first = getpass()
            if options.twice:
                second = getpass()
                if first != second:
                    parser.error('Passwords do not match.')

            if not options.raw:
                h = hashlib.new(options.hash)
                h.update(first)
                key = h.digest()
            else:
                key = first

        if options.verbose:
            print('Using key:')
            for line in textwrap.wrap(' '.join('%02x' % (ord(byte),)
                                               for byte in key),
                                      initial_indent='  ',
                                      subsequent_indent='  '):
                print(line)

    cmd = SecurityProtocolOut()

    if options.enabled:
        cmd.set_data_encryption_page.encryption_mode = 2
        cmd.set_data_encryption_page.decryption_mode = 3
        cmd.set_data_encryption_page.key = key
    else:
        cmd.set_data_encryption_page.encryption_mode = 0
        cmd.set_data_encryption_page.decryption_mode = 0
        cmd.set_data_encryption_page.key = '\x00' * 32

    cmdbuf = cmd.to_buf()
    transferbuf = cmd.set_data_encryption_page.to_buf()

    sgrawcmd = ['/usr/bin/env', 'sg_raw']
    sgrawcmd.append('--send=%d' % (len(transferbuf),))
    sgrawcmd.append(device)
    sgrawcmd.extend(('%02x' % (ord(byte),) for byte in cmdbuf))

    if options.verbose:
        print('Running:')
        for line in textwrap.wrap(' '.join(sgrawcmd),
                                  initial_indent='  ',
                                  subsequent_indent='  '):
            print(line)
        print('Transfering:')
        for line in textwrap.wrap(' '.join('%02x' % (ord(byte),)
                                           for byte in transferbuf),
                                  initial_indent='  ',
                                  subsequent_indent='  '):
            print(line)

    p = Popen(sgrawcmd, stdin=PIPE)
    if p.returncode is None:
        stdoutdata, stderrdata = p.communicate(transferbuf)

    if options.verbose:
        print('Exited: %d' % (p.returncode,))

    if p.returncode >= 0:
        sys.exit(p.returncode)
    else:
        os.kill(os.getpid(), os.WTERMSIG(p.returncode))

if __name__ == '__main__':
    main()
