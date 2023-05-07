const std = @import("std");

const Error = error {
    WrongArgsNum,
    WrongKey,
    WrongInputFile,
    WrongOutputFile,
    WrongArg,
    FileWritingError
};

const AlgorithmDescriptor = struct {
    key: u64,
    subkeys: [16]u48 = .{0} ** 16, 
    decrypt: bool,
    input_file: std.fs.File = undefined,
    output_file: std.fs.File = undefined
};


fn printHelp() void {
    std.log.info(
        "[usage] DES [-d] -k[x] <key:[8B/16B]> -i <input_file_path> -o <output_file_path\n" ++
        "   -x    : key in hex format\n" ++
        "   -d    : decrypt(default encrypt)\n" ++
        "  --help : print this message", .{}
    );
}

fn parseArgs(args: [][:0]u8) Error!AlgorithmDescriptor {
    if (args.len > 8 or args.len < 7) {
        printHelp();
        return error.WrongArgsNum;
    }

    const decrypt = std.mem.eql(u8, args[1], "-d");

    if (decrypt and args.len != 8) {
        printHelp();
        return error.WrongArgsNum;
    }

    if (!std.mem.eql(u8, args[1 + @as(usize, @boolToInt(decrypt))][0..2], "-k")) {
        printHelp();
        return error.WrongArg;
    }

    const key_in_hex = std.mem.eql(u8, args[1 + @as(usize, @boolToInt(decrypt))], "-kx");

    const key_str = args[2 + @as(usize, @boolToInt(decrypt))];
    if ((!key_in_hex and key_str.len != 8) and key_str.len != 16) {
        printHelp();
        return error.WrongKey;
    }

    var key: u64 = 0; 
    if (key_in_hex) {
        var i: u6 = 0;
        while (i < 16) : (i += 1) {
            const key_char = key_str[@as(usize, i)];
            var offset: u8 = 0;
            if (key_char >= '0' and key_char <= '9') {
                offset = '0';
            } else if (key_char >= 'A' and key_char <= 'F') {
                offset = 'A' - 10;
            } else if (key_char >= 'a' and key_char <= 'f') {
                offset = 'a' - 10;                 
            } else {
                printHelp();
                return error.WrongKey;
            }

            key |= (@as(u64, @truncate(u4, key_char - offset)) << ((15 - i) * 4));
        }
    } else {
        var i: u6 = 0;
        while (i < 8) : (i += 1) {
            key |= (@as(u64, key_str[@as(usize, i)]) << (i * 8));
        }
    }

    if (!std.mem.eql(u8, args[3 + @as(usize, @boolToInt(decrypt))], "-i")) {
        printHelp();
        return error.WrongArg;
    }
    
    const intput_file = std.fs.cwd().openFileZ(
        args[4 + @as(usize, @boolToInt(decrypt))], 
        .{ .mode = .read_only }
    ) catch {
        printHelp();
        return error.WrongInputFile;
    };

    if (!std.mem.eql(u8, args[5 + @as(usize, @boolToInt(decrypt))], "-o")) {
        printHelp();
        return error.WrongArg;
    }

    const output_file = std.fs.cwd().createFileZ(
        args[6 + @as(usize, @boolToInt(decrypt))], 
        .{ .truncate = true }
    ) catch {
        printHelp();
        return error.WrongOutputFile;
    };

    return AlgorithmDescriptor{
        .key = key,
        .decrypt = decrypt,
        .input_file = intput_file,
        .output_file = output_file
    };
}

fn convertBlockToU64(block: [8]u8) u64 {
    var result: u64 = 0;
    for (&block, 0..) |value, i| {
        result |= (@as(u64, value) << @intCast(u6, (7 - i) * 8));
    }
    return result;
}
fn convertU64ToBlock(value: u64, block: *[8]u8) void {
    for (block, 0..) |*block_value, i| {
        block_value.* = @truncate(u8, ((value >> @intCast(u6, (7 - i) * 8)) & @as(u64, 0xFF)));
    }
}

fn feistel(Rn: u32, key: u48) u32 {
    var expanded_rn: u48 = 0;
    for (&E_BIT_SELECTION, 0..) |p, i| {
        expanded_rn |= (@as(u48, ((@as(u32, 1) << @intCast(u5, 31-(p-1))) & Rn) >> @intCast(u5, 31-(p-1))) << @intCast(u6, 47 - i));
    }

    const xored_expanded_rn: u48 = expanded_rn ^ key;

    var result: u32 = 0;
    var i: usize = 0;
    while (i < S_TABLES.len) : (i += 1) {
        const index: u6 = @truncate(u6, xored_expanded_rn >> @intCast(u6, 6 * ((S_TABLES.len - 1) - i)));

        const normalized_index: u6 = (@as(u6, 0xF) & index >> 1) + 16 * ((index & @as(u6, 0x1)) | ((index >> 4) & @as(u6, 0x2)));

        result |= (@as(u32, S_TABLES[i][@as(usize, normalized_index)]) << @intCast(u5, 4 * ((S_TABLES.len - 1) - i)));
    }

    var permuted_result: u32 = 0; 
    for (&P, 0..) |p, j| {
        permuted_result |= (((@as(u32, 1) << @intCast(u5, 31-(p-1))) & result) >> @intCast(u5, 31-(p-1))) << @intCast(u5, 31 - j);
    }

    return permuted_result;
}

fn encode(block: *[8]u8, subkeys: [16]u48) void {
    const block_as_int = convertBlockToU64(block.*);
    var out: u64 = 0;
    for (&IP, 0..) |p, i| {
        out |= @intCast(u64, ((@as(u64, @as(u64, 1) << (63-(@intCast(u6,p-1)))) & block_as_int) >> (63-@intCast(u6,p-1))) << @intCast(u6, 63 - i));
    }

    var lhs: u32 = @truncate(u32, (out >> 32));
    var rhs: u32 = @truncate(u32, out);

    var i: usize = 0;
    while (i < 16) : (i += 1) {
        const subkey = subkeys[i];

        const tmp = lhs; 
        lhs = rhs;
        rhs = tmp ^ feistel(rhs, subkey);
    }

    var R16L16: u64 = (@as(u64, rhs) << 32) | @as(u64, lhs);
    out = 0;
    for (&IP_1, 0..) |p, j| {
        out |= (((@as(u64, 1) << @intCast(u6, 63-(p-1))) & R16L16) >> @intCast(u6, 63-(p-1))) << @intCast(u6, 63 - j);
    }
    
    convertU64ToBlock(out, block);
}



fn perform(alg_descriptor: AlgorithmDescriptor) !void {
    const input_file_reader = alg_descriptor.input_file.reader();
    const output_file_writer = alg_descriptor.output_file.writer();

    var buffer: [32 * 8]u8 = .{0} ** 256;
    while (true) {
        var bytes_read = try input_file_reader.read(buffer[0..]);

        if (bytes_read < buffer.len) {
            std.mem.set(u8, buffer[bytes_read..], 0);
        }

        var i: usize = 0;
        while(i < bytes_read/8 + @boolToInt(bytes_read%8 != 0)) : (i += 1) {
            var block = buffer[(i*8)..((i+1)*8)];
            encode(block[0..8], alg_descriptor.subkeys);
        }

        var bytes_written = try output_file_writer.write(buffer[0..bytes_read]);
        if (bytes_written != bytes_read) {
            return error.FileWritingError;
        }

        if (bytes_read < buffer.len) {
            break;
        }
    }
}

fn generateKeys(key: u64, subkeys: *[16]u48) void {
    var stripped_key: u56 = 0;
    for (&PC1, 0..) |p, i| {
        stripped_key |= @intCast(u56, ((@as(u64, @as(u64, 1) << (63-(p-1))) & key) >> (63-(p-1))) << @intCast(u6, 55 - i));
    }

    var key_lhs: u28 = @intCast(u28, (stripped_key & @as(u56, 0xF_FF_FF_FF) << @intCast(u6, 28)) >> @intCast(u6, 28));
    var key_rhs: u28 = @intCast(u28, stripped_key & @as(u56, 0xF_FF_FF_FF));

    var i: usize = 0;
    while (i < 16) : (i += 1) {
        var k: u2 = 0;
        while (k < ROTATIONS[i]) : (k += 1) {
            key_lhs = (key_lhs << 1) | (key_lhs & @as(u28, 1 << 27)) >> 27;
            key_rhs = (key_rhs << 1) | (key_rhs & @as(u28, 1 << 27)) >> 27;
        }

        const subkey: u56 = (@intCast(u56, key_lhs) << @intCast(u6, 28)) | @intCast(u56, key_rhs);
        var permutated_subkey: u48 = 0;    
        for (&PC2, 0..) |p, j| {
            permutated_subkey |= @intCast(u48, (((@as(u56, 1) << (55-(p-1))) & subkey) >> (55-(p-1))) << @intCast(u6, 47 - j));
        }
        subkeys.*[i] = permutated_subkey;
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if ((args.len == 2 and std.mem.eql(u8, args[1], "--help"))) {
        printHelp();
        return;
    }
    var alg_descriptor = try parseArgs(args);

    generateKeys(alg_descriptor.key, &alg_descriptor.subkeys);

    if (alg_descriptor.decrypt) {
        std.mem.reverse(u48, alg_descriptor.subkeys[0..]);
    } 

    try perform(alg_descriptor);
    alg_descriptor.input_file.close();
    alg_descriptor.output_file.close();
}

// KEY GEN
const PC1 = [_]u6{
    57, 49, 41, 33, 25, 17, 9 ,	1,
    58, 50, 42, 34, 26, 18, 10, 2,
    59, 51, 43, 35, 27, 19, 11, 3,
    60,	52, 44, 36, 63, 55, 47, 39,
    31,	23, 15, 7 ,	62, 54, 46, 38,
    30,	22, 14, 6 ,	61, 53, 45, 37,
    29,	21, 13, 5 ,	28, 20, 12, 4 
};

const PC2 = [_]u6{
    14, 17, 11, 24,  1,  5,  3, 28,
    15,  6, 21, 10, 23, 19, 12,  4,
    26,  8, 16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56,
    34, 53, 46, 42, 50, 36, 29, 32
};

const ROTATIONS = [_]u2{
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 
};

// ENCRYPTION
const IP = [_]u7{
    58,    50,   42,    34,    26,   18,    10,    2, 
    60,    52,   44,    36,    28,   20,    12,    4,
    62,    54,   46,    38,    30,   22,    14,    6,
    64,    56,   48,    40,    32,   24,    16,    8,
    57,    49,   41,    33,    25,   17,     9,    1,
    59,    51,   43,    35,    27,   19,    11,    3,
    61,    53,   45,    37,    29,   21,    13,    5,
    63,    55,   47,    39,    31,   23,    15,    7,
};

const P = [_]u6 {
    16,   7,  20,  21, 
    29,  12,  28,  17,
     1,  15,  23,  26,
     5,  18,  31,  10,
     2,   8,  24,  14,
    32,  27,   3,   9,
    19,  13,  30,   6,
    22,  11,   4,  25,
};

const E_BIT_SELECTION = [_]u7{
    32,     1,    2,     3,     4,    5, 
     4,     5,    6,     7,     8,    9,
     8,     9,   10,    11,    12,   13,
    12,    13,   14,    15,    16,   17,
    16,    17,   18,    19,    20,   21,
    20,    21,   22,    23,    24,   25,
    24,    25,   26,    27,    28,   29,
    28,    29,   30,    31,    32,    1,
};

const IP_1 = [_]u7{
    40,     8,   48,    16,    56,   24,    64,   32, 
    39,     7,   47,    15,    55,   23,    63,   31,
    38,     6,   46,    14,    54,   22,    62,   30,
    37,     5,   45,    13,    53,   21,    61,   29,
    36,     4,   44,    12,    52,   20,    60,   28,
    35,     3,   43,    11,    51,   19,    59,   27,
    34,     2,   42,    10,    50,   18,    58,   26,
    33,     1,   41,     9,    49,   17,    57,   25,
};

const S_TABLES = [8][64]u4{
    .{
     14,  4,  13,  1,   2, 15,  11,  8,   3, 10,   6, 12,   5,  9,   0,  7, 
      0, 15,   7,  4,  14,  2,  13,  1,  10,  6,  12, 11,   9,  5,   3,  8,
      4,  1,  14,  8,  13,  6,   2, 11,  15, 12,   9,  7,   3, 10,   5,  0,
     15, 12,   8,  2,   4,  9,   1,  7,   5, 11,   3, 14,  10,  0,   6, 13,
    },
    .{    
     15,  1,   8, 14,   6, 11,   3,  4,   9,  7,   2, 13,  12,  0,   5, 10, 
      3, 13,   4,  7,  15,  2,   8, 14,  12,  0,   1, 10,   6,  9,  11,  5,
      0, 14,   7, 11,  10,  4,  13,  1,   5,  8,  12,  6,   9,  3,   2, 15,
     13,  8,  10,  1,   3, 15,   4,  2,  11,  6,   7, 12,   0,  5,  14,  9,
    },
    .{
     10,  0,   9, 14,   6,  3,  15,  5,   1, 13,  12,  7,  11,  4,   2,  8, 
     13,  7,   0,  9,   3,  4,   6, 10,   2,  8,   5, 14,  12, 11,  15,  1,
     13,  6,   4,  9,   8, 15,   3,  0,  11,  1,   2, 12,   5, 10,  14,  7,
      1, 10,  13,  0,   6,  9,   8,  7,   4, 15,  14,  3,  11,  5,   2, 12,
    },
    .{
      7, 13,  14,  3,   0,  6,   9, 10,   1,  2,   8,  5,  11, 12,   4, 15, 
     13,  8,  11,  5,   6, 15,   0,  3,   4,  7,   2, 12,   1, 10,  14,  9,
     10,  6,   9,  0,  12, 11,   7, 13,  15,  1,   3, 14,   5,  2,   8,  4,
      3, 15,   0,  6,  10,  1,  13,  8,   9,  4,   5, 11,  12,  7,   2, 14,
    },
    .{
      2, 12,   4,  1,   7, 10,  11,  6,   8,  5,   3, 15,  13,  0,  14,  9, 
     14, 11,   2, 12,   4,  7,  13,  1,   5,  0,  15, 10,   3,  9,   8,  6,
      4,  2,   1, 11,  10, 13,   7,  8,  15,  9,  12,  5,   6,  3,   0, 14,
     11,  8,  12,  7,   1, 14,   2, 13,   6, 15,   0,  9,  10,  4,   5,  3,
    },
    .{
     12,  1,  10, 15,   9,  2,   6,  8,   0, 13,   3,  4,  14,  7,   5, 11, 
     10, 15,   4,  2,   7, 12,   9,  5,   6,  1,  13, 14,   0, 11,   3,  8,
      9, 14,  15,  5,   2,  8,  12,  3,   7,  0,   4, 10,   1, 13,  11,  6,
      4,  3,   2, 12,   9,  5,  15, 10,  11, 14,   1,  7,   6,  0,   8, 13,
    },
    .{
      4, 11,   2, 14,  15,  0,   8, 13,   3, 12,   9,  7,   5, 10,   6,  1, 
     13,  0,  11,  7,   4,  9,   1, 10,  14,  3,   5, 12,   2, 15,   8,  6,
      1,  4,  11, 13,  12,  3,   7, 14,  10, 15,   6,  8,   0,  5,   9,  2,
      6, 11,  13,  8,   1,  4,  10,  7,   9,  5,   0, 15,  14,  2,   3, 12,
    },
    .{
     13,  2,   8,  4,   6, 15,  11,  1,  10,  9,   3, 14,   5,  0,  12,  7, 
      1, 15,  13,  8,  10,  3,   7,  4,  12,  5,   6, 11,   0, 14,   9,  2,
      7, 11,   4,  1,   9, 12,  14,  2,   0,  6,  10, 13,  15,  3,   5,  8,
      2,  1,  14,  7,   4, 10,   8, 13,  15, 12,   9,  0,   3,  5,   6, 11,
    }
};


// TESTS //
test "Test keys generation" {
    const correct_subkeys = [_]u48{
        0b000110110000001011101111111111000111000001110010,
        0b011110011010111011011001110110111100100111100101,
        0b010101011111110010001010010000101100111110011001,
        0b011100101010110111010110110110110011010100011101,
        0b011111001110110000000111111010110101001110101000,
        0b011000111010010100111110010100000111101100101111,
        0b111011001000010010110111111101100001100010111100,
        0b111101111000101000111010110000010011101111111011,
        0b111000001101101111101011111011011110011110000001,
        0b101100011111001101000111101110100100011001001111,
        0b001000010101111111010011110111101101001110000110,
        0b011101010111000111110101100101000110011111101001,
        0b100101111100010111010001111110101011101001000001,
        0b010111110100001110110111111100101110011100111010,
        0b101111111001000110001101001111010011111100001010,
        0b110010110011110110001011000011100001011111110101,
    };

    const key: u64 = 0x133457799BBCDFF1;

    var subkeys: [16]u48 = .{0} ** 16;

    generateKeys(key, &subkeys);

    for (&subkeys, &correct_subkeys) |subkey, correct_subkey| {
        try std.testing.expect(subkey == correct_subkey);
    } 
}


test "Test encryption" {
    const key: u64 = 0x133457799BBCDFF1;
    var subkeys: [16]u48 = .{0} ** 16;
    generateKeys(key, &subkeys);

    var input_file = try std.fs.cwd().openFile(
        "in.txt",
        .{ .mode = .read_only }
    );
    var output_file = try std.fs.cwd().createFile(
        "tmp_out.txt",
        .{ .truncate = true }
    );
    
    try perform(.{
        .key = key,
        .subkeys = subkeys,
        .decrypt = false,
        .input_file = input_file,
        .output_file = output_file
    });

    input_file.close();
    output_file.close();

    output_file = try std.fs.cwd().openFile(
        "tmp_out.txt",
        .{ .mode = .read_only }
    );

    const correct_result: [8]u8 = .{ 0x85, 0xe8, 0x13, 0x54, 0x0f, 0x0a, 0xb4, 0x05 };
    var result: [8]u8 = .{0} ** 8;
    _ = try output_file.read(result[0..]);

    try std.testing.expect(std.mem.eql(u8, correct_result[0..], result[0..]));    

    output_file.close();
}

test "Test decryption" {
    const key: u64 = 0x133457799BBCDFF1;
    var subkeys: [16]u48 = .{0} ** 16;
    generateKeys(key, &subkeys);

    std.mem.reverse(u48, subkeys[0..]);

    var input_file = try std.fs.cwd().openFile(
        "tmp_out.txt",
        .{ .mode = .read_only }
    );
    var output_file = try std.fs.cwd().createFile(
        "tmp_in.txt",
        .{ .truncate = true }
    );
    
    try perform(.{
        .key = key,
        .subkeys = subkeys,
        .decrypt = true,
        .input_file = input_file,
        .output_file = output_file
    });

    input_file.close();
    output_file.close();

    output_file = try std.fs.cwd().openFile(
        "tmp_in.txt",
        .{ .mode = .read_only }
    );

    const correct_result: [8]u8 = .{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, };
    var result: [8]u8 = .{0} ** 8;
    _ = try output_file.read(result[0..]);

    try std.testing.expect(std.mem.eql(u8, correct_result[0..], result[0..]));  

    output_file.close();
}