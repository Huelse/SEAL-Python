import os

root_path = './SEAL/native/src/seal/'
files = ['plaintext.h', 'ciphertext.h', 'kswitchkeys.h', 'secretkey.h', 'publickey.h']
keyword = 'private:'
new_line = 'EncryptionParameters parms;'

def add_parms_to_header():
    for file_name in files:
        file_path = root_path + file_name
        if os.path.exists(file_path):
            new_line_exists = True
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                for line in lines:
                    if new_line in line:
                        new_line_exists = False

            if new_line_exists:
                with open(file_path, 'w', encoding='utf-8') as fs:
                    for line in lines:
                        if keyword in line:
                            line = line.replace(line, '\t\t{}\n\n\t{}\n'.format(new_line, keyword))
                        fs.write(line)
                    print('Add parms to {} success.'. format(file_path))
        else:
            print('Can not find the {}, please check the file integrity.'.format(file_path))


def switch_wrapper():
    ifswitch = False
    with open('./setup.py', 'r', encoding='utf-8') as f:
        lines = f.readlines()
        for line in lines:
            if "wrapper_file = 'src/wrapper.cpp'" in line:
                ifswitch = True
    if ifswitch:
        with open('./setup.py', 'w', encoding='utf-8') as fs:
            for line in lines:
                if "wrapper_file = 'src/wrapper.cpp'" in line:
                    line = line.replace(line, "wrapper_file = 'src/wrapper_with_pickle.cpp'\n")
                fs.write(line)
            print("Switch wrapper success.")
    else:
        print('Already switch to wrapper with pickle.')


if __name__ == '__main__':
    add_parms_to_header()
    switch_wrapper()
