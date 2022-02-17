
# Implements [System.StringComparer]::InvariantcultureIgnoreCase.GetHashCode()


"""
key byte dump
0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
grabbing a sort key for "/"
length of sort key: 7
key byte dump
7 35 1 1 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0
grabbing a sort key for "A"
length of sort key: 7
key byte dump
e 2 1 1 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0
grabbing a sort key for "S"
length of sort key: 7
key byte dump
e 91 1 1 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0
grabbing a sort key for "P"
length of sort key: 7
key byte dump
e 7e 1 1 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0
...
individual key length 46 sum
sort key length for entire string: 19
entire string: "/ASPTester"
key byte dump
7 35 e 2 e 91 e 7e e 99 e 21 e 91 e 99 e 21 e 8a 1 1 1 1 0

^^ It's actually more complicated than this when charactes such as - and '
are included
"""
sort_key_lookup = {
# sort key for "a"
"\x61\x00":"\x0e\x02\x01\x01\x01\x01\x00",
# sort key for "b"
"\x62\x00":"\x0e\x09\x01\x01\x01\x01\x00",
# sort key for "c"
"\x63\x00":"\x0e\x0a\x01\x01\x01\x01\x00",
# sort key for "d"
"\x64\x00":"\x0e\x1a\x01\x01\x01\x01\x00",
# sort key for "e"
"\x65\x00":"\x0e\x21\x01\x01\x01\x01\x00",
# sort key for "f"
"\x66\x00":"\x0e\x23\x01\x01\x01\x01\x00",
# sort key for "g"
"\x67\x00":"\x0e\x25\x01\x01\x01\x01\x00",
# sort key for "h"
"\x68\x00":"\x0e\x2c\x01\x01\x01\x01\x00",
# sort key for "i"
"\x69\x00":"\x0e\x32\x01\x01\x01\x01\x00",
# sort key for "j"
"\x6a\x00":"\x0e\x35\x01\x01\x01\x01\x00",
# sort key for "k"
"\x6b\x00":"\x0e\x36\x01\x01\x01\x01\x00",
# sort key for "l"
"\x6c\x00":"\x0e\x48\x01\x01\x01\x01\x00",
# sort key for "m"
"\x6d\x00":"\x0e\x51\x01\x01\x01\x01\x00",
# sort key for "n"
"\x6e\x00":"\x0e\x70\x01\x01\x01\x01\x00",
# sort key for "o"
"\x6f\x00":"\x0e\x7c\x01\x01\x01\x01\x00",
# sort key for "p"
"\x70\x00":"\x0e\x7e\x01\x01\x01\x01\x00",
# sort key for "q"
"\x71\x00":"\x0e\x89\x01\x01\x01\x01\x00",
# sort key for "r"
"\x72\x00":"\x0e\x8a\x01\x01\x01\x01\x00",
# sort key for "s"
"\x73\x00":"\x0e\x91\x01\x01\x01\x01\x00",
# sort key for "t"
"\x74\x00":"\x0e\x99\x01\x01\x01\x01\x00",
# sort key for "u"
"\x75\x00":"\x0e\x9f\x01\x01\x01\x01\x00",
# sort key for "v"
"\x76\x00":"\x0e\xa2\x01\x01\x01\x01\x00",
# sort key for "w"
"\x77\x00":"\x0e\xa4\x01\x01\x01\x01\x00",
# sort key for "x"
"\x78\x00":"\x0e\xa6\x01\x01\x01\x01\x00",
# sort key for "y"
"\x79\x00":"\x0e\xa7\x01\x01\x01\x01\x00",
# sort key for "z"
"\x7a\x00":"\x0e\xa9\x01\x01\x01\x01\x00",
# sort key for "A"
"\x41\x00":"\x0e\x02\x01\x01\x01\x01\x00",
# sort key for "B"
"\x42\x00":"\x0e\x09\x01\x01\x01\x01\x00",
# sort key for "C"
"\x43\x00":"\x0e\x0a\x01\x01\x01\x01\x00",
# sort key for "D"
"\x44\x00":"\x0e\x1a\x01\x01\x01\x01\x00",
# sort key for "E"
"\x45\x00":"\x0e\x21\x01\x01\x01\x01\x00",
# sort key for "F"
"\x46\x00":"\x0e\x23\x01\x01\x01\x01\x00",
# sort key for "G"
"\x47\x00":"\x0e\x25\x01\x01\x01\x01\x00",
# sort key for "H"
"\x48\x00":"\x0e\x2c\x01\x01\x01\x01\x00",
# sort key for "I"
"\x49\x00":"\x0e\x32\x01\x01\x01\x01\x00",
# sort key for "J"
"\x4a\x00":"\x0e\x35\x01\x01\x01\x01\x00",
# sort key for "K"
"\x4b\x00":"\x0e\x36\x01\x01\x01\x01\x00",
# sort key for "L"
"\x4c\x00":"\x0e\x48\x01\x01\x01\x01\x00",
# sort key for "M"
"\x4d\x00":"\x0e\x51\x01\x01\x01\x01\x00",
# sort key for "N"
"\x4e\x00":"\x0e\x70\x01\x01\x01\x01\x00",
# sort key for "O"
"\x4f\x00":"\x0e\x7c\x01\x01\x01\x01\x00",
# sort key for "P"
"\x50\x00":"\x0e\x7e\x01\x01\x01\x01\x00",
# sort key for "Q"
"\x51\x00":"\x0e\x89\x01\x01\x01\x01\x00",
# sort key for "R"
"\x52\x00":"\x0e\x8a\x01\x01\x01\x01\x00",
# sort key for "S"
"\x53\x00":"\x0e\x91\x01\x01\x01\x01\x00",
# sort key for "T"
"\x54\x00":"\x0e\x99\x01\x01\x01\x01\x00",
# sort key for "U"
"\x55\x00":"\x0e\x9f\x01\x01\x01\x01\x00",
# sort key for "V"
"\x56\x00":"\x0e\xa2\x01\x01\x01\x01\x00",
# sort key for "W"
"\x57\x00":"\x0e\xa4\x01\x01\x01\x01\x00",
# sort key for "X"
"\x58\x00":"\x0e\xa6\x01\x01\x01\x01\x00",
# sort key for "Y"
"\x59\x00":"\x0e\xa7\x01\x01\x01\x01\x00",
# sort key for "Z"
"\x5a\x00":"\x0e\xa9\x01\x01\x01\x01\x00",
# sort key for "0"
"\x30\x00":"\x0d\x03\x01\x01\x01\x01\x00",
# sort key for "1"
"\x31\x00":"\x0d\x1a\x01\x01\x01\x01\x00",
# sort key for "2"
"\x32\x00":"\x0d\x1c\x01\x01\x01\x01\x00",
# sort key for "3"
"\x33\x00":"\x0d\x1e\x01\x01\x01\x01\x00",
# sort key for "4"
"\x34\x00":"\x0d\x20\x01\x01\x01\x01\x00",
# sort key for "5"
"\x35\x00":"\x0d\x22\x01\x01\x01\x01\x00",
# sort key for "6"
"\x36\x00":"\x0d\x24\x01\x01\x01\x01\x00",
# sort key for "7"
"\x37\x00":"\x0d\x26\x01\x01\x01\x01\x00",
# sort key for "8"
"\x38\x00":"\x0d\x28\x01\x01\x01\x01\x00",
# sort key for "9"
"\x39\x00":"\x0d\x2a\x01\x01\x01\x01\x00",
# sort key for "-"
# UHOH! we may not have the full key for -!
"\x2d\x00":"\x01\x01\x01\x01\xff\xff\x82\x12\x00",
# sort key for "."
"\x2e\x00":"\x07\x33\x01\x01\x01\x01\x00",
# sort key for "_"
"\x5f\x00":"\x07\x44\x01\x01\x01\x01\x00",
# sort key for "~"
"\x7e\x00":"\x07\x50\x01\x01\x01\x01\x00",
# sort key for "!"
"\x21\x00":"\x07\x1c\x01\x01\x01\x01\x00",
# sort key for "$"
"\x24\x00":"\x07\x21\x01\x01\x01\x01\x00",
# sort key for "&"
"\x26\x00":"\x07\x25\x01\x01\x01\x01\x00",
# sort key for "'"
# UHOH! we may not have the full key for '!
"\x27\x00":"\x01\x01\x01\x01\xff\xff\x80\x12\x00",
# sort key for "("
"\x28\x00":"\x07\x27\x01\x01\x01\x01\x00",
# sort key for ")"
"\x29\x00":"\x07\x2a\x01\x01\x01\x01\x00",
# sort key for "*"
"\x2a\x00":"\x07\x2d\x01\x01\x01\x01\x00",
# sort key for "+"
"\x2b\x00":"\x08\x03\x01\x01\x01\x01\x00",
# sort key for ","
"\x2c\x00":"\x07\x2f\x01\x01\x01\x01\x00",
# sort key for ";"
"\x3b\x00":"\x07\x3a\x01\x01\x01\x01\x00",
# sort key for "="
"\x3d\x00":"\x08\x12\x01\x01\x01\x01\x00",
# sort key for ":"
"\x3a\x00":"\x07\x37\x01\x01\x01\x01\x00",
# sort key for "@"
"\x40\x00":"\x07\x3e\x01\x01\x01\x01\x00",
# sort key for "%"
"\x25\x00":"\x07\x23\x01\x01\x01\x01\x00",
# sort key for "/"
"\x2f\x00":"\x07\x35\x01\x01\x01\x01\x00",
}
def get_sort_key(string, encoding_type="utf-16le"):
    if len(string) == 0:
        return ""
    
    # NOTE: we only support ASCII (as that's what more or less is what's allowed
    # in URL paths) but we've made this table so that is easy for interested 
    # parties to extend :)
    builder = []
    ending = []


    # when we have a duplicate special character we only repeat the last
    # encoding
    last_encoding = {}

    last_char = None
    repeat_count = 0
    for (index, i) in enumerate(string):
        if i == last_char:
            repeat_count += 1
        else:
            repeat_count = 0


        sort_key = sort_key_lookup.get(i.encode(encoding_type))

        if sort_key == None:
            raise Exception("IIS app path has a character (%c) we have no search key for" % i)
        
        if sort_key.startswith("\x01\x01\x01\x01"):
            real_key = sort_key[4:-1]
            
            if repeat_count == 0:
                start_idx = index if repeat_count == 0 else index-repeat_count
            
                
                counter = 0xff - (start_idx - len(ending))
                final_key = real_key[0] + chr(counter) + real_key[2:]
                ending.append(final_key)

                last_encoding[i] = final_key
            else:
                ending.append(last_encoding[i])
        else:
            real_key = sort_key[:2]
            builder.append(real_key)

            
        last_char = i
    
    builder.append("\x01\x01\x01\x01")
    builder.extend(ending)
    builder.append("\x00")

    return "".join(builder)

def get_hash_code(string, bit_width=32):
    state = 0
    something = 5381
    other = 5381
    processor_mask = (2**(bit_width))-1
    
    for str_byte in string:
        byte = ord(str_byte)
        if state == 0:
            if byte == 0:
                break
            something = (((something * 33 )& processor_mask) ^ byte ) & processor_mask
            state = 1
        elif state == 1:
            if byte == 0:
                break
            other = (((other * 33) & processor_mask) ^ byte) & processor_mask
            state = 0

    final_mul = ((other * 0x5D588B65) & processor_mask)
    result = ((final_mul + something) & processor_mask)

    return result

def str_get_hash_code(string):
    if len(string) != 0:
        sort_key = get_sort_key(string)
        hash_code = get_hash_code(sort_key)

        return hash_code
    else:
        return 0

def get_class_name(file_name):
    builder = []
    for (index, i) in enumerate(file_name):
        if index == 0:
            if not i.isalpha():
                builder.append("_")

        if not i.isalnum():
            builder.append("_")
        elif i.isdigit():
            builder.append(i)
        else:
            builder.append(i.lower())

    return "".join(builder)

def default_mac_key_modifier(path):
    # In order to get a MAC "modifier"/"generator" (it's an IIS
    # anti-CSRF measure) we:
    # 1) convert the page name into an ASP .NET class name
    # 2) get its hash code
    # 3) normalize the path preceeding that file name and hash that
    # 4) add both together
    parts = path.split("/")
    
    file_name = parts[-1]
    class_name = get_class_name(file_name)
    class_hash = str_get_hash_code(class_name)
    
    template_path = "/".join(parts[:-1]) if len(parts) > 2 else "/"
    template_hash = str_get_hash_code(template_path)

    return (template_hash + class_hash) & 0xffffffff


if __name__ == "__main__":
    assert default_mac_key_modifier("/ASPTester/whoareyou.aspx") == 0x0dd996f5
    assert default_mac_key_modifier("/ASPTester/NoReallyWho.aspx") == 0xed6334e2
    assert default_mac_key_modifier("/ASPTester/I-am-Not!real.aspx") == 0x93ed6e36
    assert default_mac_key_modifier("/ASPTester/9I-am-Not'real.aspx") == 0xead75462
    assert default_mac_key_modifier("/ASPTester/-__@.aspx") == 0x0d9090d5
    default_mac_key_modifier("/index.aspx") == 0x90059987
    

"""
import binascii
import dotnet
import System.StringComparer

def make_binary(string):
    if len(string) != 0:
        return "".join([chr(int(x,16)) for x in string.split(" ")])
    else:
        return ""

def make_string(binary_string):
    return " ".join(["%02x" % ord(x) for x in binary_string])


def get_diff_offset(one, two):
    print "one:", one
    print "two:", two
    for (index, pair) in enumerate(zip(one, two)):
        a = pair[0]
        b = pair[1]
        if a != b:
            return index
    return None


def test(string, expected_result):
    print "testing on string: \"%s\"" % string
    result = get_sort_key(string)
    correct_result = make_binary(expected_result)
    if result != correct_result:
        print "correct result:", expected_result
        print "actual  result:", make_string(result)

    offset = get_diff_offset(correct_result, result)
    if offset != None:
        print "first differing offset:", offset
        
    assert result == correct_result


def test_hash_code_random():
    from random import randint, choice
    
    alphabet = sort_key_lookup.keys()
    while True:
        sample_count = randint(0, 100)
        
        string = "".join([choice(alphabet) for i in range(0, sample_count)])
        decoded_string = str(string.decode("utf-16le"))
        
        print "testing string: %s" % decoded_string
        
        real_hash_code = System.StringComparer.InvariantCultureIgnoreCase.GetHashCode(decoded_string)
        
        if real_hash_code < 0:
            real_hash_code = ~real_hash_code ^ 0xffffffff
        
        hash_code = str_get_hash_code(decoded_string)

        if hash_code != real_hash_code:
            print "ERROR!"
            print "real hash code: %08x" % real_hash_code
            print "our hash code: %08x" % hash_code
        
        assert hash_code == real_hash_code
            
        print "----------"
    
def test_sort_key_random():
    # NN: this is bad python! Don't do this again! It will probably run regardless
    # of whether this module has this function used at all
    from ctypes import *
    from random import randint, choice
    
    alphabet = sort_key_lookup.keys()
    
    while True:
        sample_count = randint(0, 100)
        
        string = "".join([choice(alphabet) for i in range(0, sample_count)]) + "\x00\x00"
        arg_string = c_char_p(string)
        output_length = windll.kernel32.LCMapStringEx(0, 0x08000401,
                                                      arg_string,
                                                      len(string.decode('utf-16le'))-1,
                                                      0, 0, 0, 0, 0)
        output_buffer = create_string_buffer(output_length)
        windll.kernel32.LCMapStringEx(0, 0x08000401,
                                      arg_string,
                                      len(string.decode('utf-16le'))-1,
                                      output_buffer,
                                      output_length,
                                      0, 0, 0)

        test(string.decode("utf-16le")[:-1], make_string(output_buffer.raw))


# if __name__ == "__main__":
#     test("/ASPTester", "07 35 0e 02 0e 91 0e 7e 0e 99 0e 21 0e 91 0e 99 0e 21 0e 8a 01 01 01 01 00")
#     test("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~!$&'()*+,;=:@%/", "0e 02 0e 09 0e 0a 0e 1a 0e 21 0e 23 0e 25 0e 2c 0e 32 0e 35 0e 36 0e 48 0e 51 0e 70 0e 7c 0e 7e 0e 89 0e 8a 0e 91 0e 99 0e 9f 0e a2 0e a4 0e a6 0e a7 0e a9 0e 02 0e 09 0e 0a 0e 1a 0e 21 0e 23 0e 25 0e 2c 0e 32 0e 35 0e 36 0e 48 0e 51 0e 70 0e 7c 0e 7e 0e 89 0e 8a 0e 91 0e 99 0e 9f 0e a2 0e a4 0e a6 0e a7 0e a9 0d 03 0d 1a 0d 1c 0d 1e 0d 20 0d 22 0d 24 0d 26 0d 28 0d 2a 07 33 07 44 07 50 07 1c 07 21 07 25 07 27 07 2a 07 2d 08 03 07 2f 07 3a 08 12 07 37 07 3e 07 23 07 35 01 01 01 01 ff c1 82 12 ff bb 80 12 00")
#     test("-", "01 01 01 01 ff ff 82 12 00")
#     test("-!!!!!--", "07 1c 07 1c 07 1c 07 1c 07 1c 01 01 01 01 ff ff 82 12 ff fa 82 12 ff fa 82 12 00")
#     test("-'''--", "01 01 01 01 ff ff 82 12 ff ff 80 12 ff ff 80 12 ff ff 80 12 ff ff 82 12 ff ff 82 12 00")

#     test_sort_key_random()

if __name__ == "__main__":
    assert str_get_hash_code("/ASPTester") == 946421802
    assert str_get_hash_code("/glacier/tomcat/fratricide/x.aspx") == 0xe271e939
    assert str_get_hash_code("") == 0

    test_hash_code_random()
"""    
