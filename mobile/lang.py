import struct
import argparse
import sys

MAGIC_LE = b'\xde\x12\x04\x95'
MAGIC_BE = b'\x95\x04\x12\xde'
ENCODING = 'utf-8'
KEY_LENGTH = 384


def generate_fib_key(length=KEY_LENGTH):
    key = []
    a, b = 0, 1
    for i in range(length):
        if i == 0:
            key.append(0)
        else:
            key.append(b & 0xff)
            a, b = b, a + b
    return key


def xor_crypt(data, key):
    result = bytearray(len(data))
    key_len = len(key)
    str_len = len(data)

    for i in range(str_len):
        key_idx = (str_len ^ i) % key_len
        result[i] = data[i] ^ key[key_idx]

    return bytes(result)


def escape_po(s):
    """Escapes strings for PO format."""
    return s.replace('\\', '\\\\') \
            .replace('"', '\\"') \
            .replace('\n', '\\n') \
            .replace('\r', '\\r') \
            .replace('\t', '\\t')


def unescape_po(s):
    """Unescapes strings from PO format."""
    return s.replace('\\n', '\n') \
            .replace('\\r', '\r') \
            .replace('\\t', '\t') \
            .replace('\\"', '"') \
            .replace('\\\\', '\\')


def read_mo_file(input_file):
    with open(input_file, 'rb') as f:
        magic = f.read(4)
        if magic == MAGIC_LE:
            endian = '<'
        elif magic == MAGIC_BE:
            endian = '>'
        else:
            print(f"Error: Unknown file format. Magic bytes: {magic.hex()}")
            sys.exit(1)

        # Magic (4), Revision (4), Count (4), OrigOffset (4), TransOffset (4), HashSz (4), HashOff (4)
        f.seek(4)
        header_data = f.read(24)
        revision, num_strings, o_table_off, t_table_off, hash_sz, hash_off = struct.unpack(f'{endian}6I', header_data)

        header_info = {
            'revision': revision,
            'num_strings': num_strings,
            'o_table_off': o_table_off,
            't_table_off': t_table_off,
            'hash_sz': hash_sz,
            'hash_off': hash_off,
            'endian': endian,
        }

        entries = []
        for i in range(num_strings):
            # Original String (msgid)
            f.seek(o_table_off + (i * 8))
            o_len, o_off = struct.unpack(f'{endian}II', f.read(8))

            # Translated String (msgstr)
            f.seek(t_table_off + (i * 8))
            t_len, t_off = struct.unpack(f'{endian}II', f.read(8))

            # Read the actual bytes
            f.seek(o_off)
            msgid_raw = f.read(o_len)

            f.seek(t_off)
            msgstr_raw = f.read(t_len)

            entries.append((msgid_raw, msgstr_raw))

    return entries, header_info


def write_mo_file(output_file, entries):
    num_strings = len(entries)

    header_size = 28
    table_item_size = 8

    o_table_offset = header_size
    t_table_offset = header_size + (num_strings * table_item_size)
    text_start_offset = t_table_offset + (num_strings * table_item_size)

    o_table_blob = bytearray()
    t_table_blob = bytearray()
    text_blob = bytearray()

    current_text_offset = text_start_offset

    for msgid_bytes, msgstr_bytes in entries:
        id_bytes = msgid_bytes + b'\x00'
        str_bytes = msgstr_bytes + b'\x00'

        o_table_blob.extend(struct.pack('<II', len(id_bytes)-1, current_text_offset))
        text_blob.extend(id_bytes)
        current_text_offset += len(id_bytes)

        t_table_blob.extend(struct.pack('<II', len(str_bytes)-1, current_text_offset))
        text_blob.extend(str_bytes)
        current_text_offset += len(str_bytes)

    with open(output_file, 'wb') as f:
        # Header
        # Magic (LE), Revision (0), Count, O_Off, T_Off, HashSz (0), HashOff (0)
        # Hash Size is 0 because we are keeping the file unsorted.
        f.write(struct.pack('<IIIIIII',
                            0x950412de,
                            0,
                            num_strings,
                            o_table_offset,
                            t_table_offset,
                            0, 0))

        # Tables
        f.write(o_table_blob)
        f.write(t_table_blob)

        # Data
        f.write(text_blob)


def decrypt(args):
    input_file = args.input
    output_file = args.output

    print(f"Reading {input_file}...")
    entries_raw, header_info = read_mo_file(input_file)

    num_strings = header_info['num_strings']
    print(f"Found {num_strings} messages. Decrypting...")

    key = generate_fib_key()

    entries = []
    for msgid_raw, msgstr_raw in entries_raw:
        msgid_dec = xor_crypt(msgid_raw, key)
        msgstr_dec = xor_crypt(msgstr_raw, key)

        # Decode
        try:
            msgid = msgid_dec.decode(ENCODING)
            msgstr = msgstr_dec.decode(ENCODING)
        except UnicodeDecodeError:
            # Fallback if bytes are weird
            msgid = msgid_dec.decode(ENCODING, errors='replace')
            msgstr = msgstr_dec.decode(ENCODING, errors='replace')

        entries.append((msgid, msgstr))

    with open(output_file, 'w', encoding=ENCODING) as out:
        out.write(f'# Decrypted from {input_file}\n\n')

        for msgid, msgstr in entries:
            out.write(f'msgid "{escape_po(msgid)}"\n')
            out.write(f'msgstr "{escape_po(msgstr)}"\n\n')

    print(f"Success! Decrypted to {output_file}")


def encrypt(args):
    input_file = args.input
    output_file = args.output

    print(f"Parsing {input_file}...")

    entries = []
    current_msgid = None
    current_msgstr = None

    with open(input_file, 'r', encoding=ENCODING) as f:
        lines = f.readlines()

    for line in lines:
        line = line.strip()
        if line.startswith('msgid "'):
            current_msgid = unescape_po(line[7:-1])
        elif line.startswith('msgstr "'):
            if current_msgid is not None:
                current_msgstr = unescape_po(line[8:-1])
                entries.append((current_msgid, current_msgstr))
                current_msgid = None
                current_msgstr = None

    num_strings = len(entries)
    print(f"Encrypting {num_strings} messages...")

    key = generate_fib_key()

    entries_enc = []
    for msgid, msgstr in entries:
        msgid_bytes = msgid.encode(ENCODING)
        msgstr_bytes = msgstr.encode(ENCODING)

        msgid_enc = xor_crypt(msgid_bytes, key)
        msgstr_enc = xor_crypt(msgstr_bytes, key)

        entries_enc.append((msgid_enc, msgstr_enc))

    write_mo_file(output_file, entries_enc)

    print(f"Success! Encrypted to {output_file}")


def unpack(args):
    input_file = args.input
    output_file = args.output

    print(f"Reading {input_file}...")
    entries_raw, header_info = read_mo_file(input_file)

    num_strings = header_info['num_strings']
    print(f"Found {num_strings} messages. Extracting...")

    entries = []
    for msgid_raw, msgstr_raw in entries_raw:
        # Decode
        try:
            msgid = msgid_raw.decode(ENCODING)
            msgstr = msgstr_raw.decode(ENCODING)
        except UnicodeDecodeError:
            # Fallback if bytes are weird
            msgid = msgid_raw.decode(ENCODING, errors='replace')
            msgstr = msgstr_raw.decode(ENCODING, errors='replace')

        entries.append((msgid, msgstr))

    with open(output_file, 'w', encoding=ENCODING) as out:
        out.write(f'# Unpacked from {input_file}\n')

        for msgid, msgstr in entries:
            out.write(f'msgid "{escape_po(msgid)}"\n')
            out.write(f'msgstr "{escape_po(msgstr)}"\n\n')

    print(f"Success! Unpacked to {output_file}")


def pack(args):
    input_file = args.input
    output_file = args.output

    print(f"Parsing {input_file}...")

    entries = []
    current_msgid = None
    current_msgstr = None

    with open(input_file, 'r', encoding=ENCODING) as f:
        lines = f.readlines()

    for line in lines:
        line = line.strip()
        if line.startswith('msgid "'):
            current_msgid = unescape_po(line[7:-1])
        elif line.startswith('msgstr "'):
            if current_msgid is not None:
                current_msgstr = unescape_po(line[8:-1])
                entries.append((current_msgid, current_msgstr))
                current_msgid = None
                current_msgstr = None

    num_strings = len(entries)
    print(f"Packing {num_strings} messages...")

    entries_bytes = [(msgid.encode(ENCODING), msgstr.encode(ENCODING))
                     for msgid, msgstr in entries]

    write_mo_file(output_file, entries_bytes)

    print(f"Success! Packed to {output_file}")


def main():
    parser = argparse.ArgumentParser(description="Tool for unpacking/packing/encrypting Dead Cells mobile MO files.")
    subparsers = parser.add_subparsers(dest='command', required=True)

    p_decrypt = subparsers.add_parser('decrypt', help='Decrypt MO to PO')
    p_decrypt.add_argument('input', help='Encrypted MO file')
    p_decrypt.add_argument('output', help='Output PO file')
    p_decrypt.set_defaults(func=decrypt)

    p_encrypt = subparsers.add_parser('encrypt', help='Encrypt PO to MO')
    p_encrypt.add_argument('input', help='PO file')
    p_encrypt.add_argument('output', help='Output encrypted MO file')
    p_encrypt.set_defaults(func=encrypt)

    p_unpack = subparsers.add_parser('unpack', help='Convert MO binary to readable PO text')
    p_unpack.add_argument('input', help='Input binary file (e.g., main.en.mo)')
    p_unpack.add_argument('output', help='Output text file (e.g., main.en.po)')
    p_unpack.set_defaults(func=unpack)

    p_pack = subparsers.add_parser('pack', help='Convert PO text back to binary MO')
    p_pack.add_argument('input', help='Input text file (e.g., main.en.po)')
    p_pack.add_argument('output', help='Output binary file (e.g., main.en.mo)')
    p_pack.set_defaults(func=pack)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
